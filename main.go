package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	scandaloriantypes "github.com/charles-d-burton/scandalorian-types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	messageBus MessageBus
	streams    = map[string]string{
		"discovery": "discovery.requests",
		//"zonewalk":   "zonewalk.requests", //Isn't online/ready yet
		"reversedns": "reversedns.reqeusts",
	}
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(scan *scandaloriantypes.Scan) error
	Close()
}

func main() {
	log.Info("Starting up")
	log.SetFormatter(&log.JSONFormatter{})
	v := viper.New()
	v.SetEnvPrefix("ingest")
	v.AutomaticEnv()
	if !v.IsSet("port") || !v.IsSet("host") {
		log.Fatal("Must set host and port for message bus")
	}
	bus, err := connectBus(v)
	if err != nil {
		log.Fatal(err)
	}
	defer bus.Close()
	messageBus = bus
	router := gin.Default()
	router.POST("/scan", handlePost)
	router.Run(":9090")
}

//Connect to a message bus, this is abstracted to an interface so implementations of other busses e.g. Rabbit are easier
//TODO: Clean this mess up
func connectBus(v *viper.Viper) (MessageBus, error) {
	var bus MessageBus
	if v.IsSet("bus_type") {
		busType := v.GetString("bus_type")
		switch busType {
		case "nats":
			var natsConn NatsConn
			err := natsConn.Connect(v.GetString("host"), v.GetString("port"))
			if err != nil {
				return nil, err
			}
			bus = &natsConn
		default:
			var natsConn NatsConn
			err := natsConn.Connect(v.GetString("host"), v.GetString("port"))
			if err != nil {
				return nil, err
			}
			bus = &natsConn
		}
	} else {
		var natsConn NatsConn
		err := natsConn.Connect(v.GetString("host"), v.GetString("port"))
		if err != nil {
			return nil, err
		}
		bus = &natsConn
	}
	return bus, nil
}

func handlePost(c *gin.Context) {
	var scanRequest scandaloriantypes.ScanRequest
	if err := c.ShouldBindJSON(&scanRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if scanRequest.Address == "" && scanRequest.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host or address undefined"})
		return
	} else if scanRequest.Address != "" && scanRequest.Host != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host and address defined"})
		return
	} else if scanRequest.Host != "" && strings.Contains(strings.ToLower(scanRequest.Host), "localhost") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot scan localhost"})
	}
	if scanRequest.Address != "" {
		parts := strings.Split(scanRequest.Address, "/") //Check for CIDR notation
		if len(parts) < 2 {
			scanRequest.Address = scanRequest.Address + "/32"
		} else if len(parts) > 2 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad address"})
			return
		}
		cidrval, err := strconv.Atoi(parts[1])
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if cidrval < 24 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "subnet out of range"})
			return
		}
		ip, _, err := net.ParseCIDR(scanRequest.Address)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if ip.IsLoopback() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot scan loopback"})
			return
		}
		if err := enQueueRequest(&scanRequest); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else if scanRequest.Host != "" {
		addr, err := net.LookupIP(scanRequest.Host)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown host"})
			return
		}
		fmt.Println("IP address: ", addr)
		for _, address := range addr {
			var req scandaloriantypes.ScanRequest
			req = scanRequest
			req.Address = address.String()
			if err := enQueueRequest(&scanRequest); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
	}
}

func enQueueRequest(scanreq *scandaloriantypes.ScanRequest) error {
	id := uuid.New().String()
	if len(scanreq.ScanTypes) == 0 {
		keys := make([]string, len(streams))
		i := 0
		for k := range streams {
			keys[i] = k
			i++
		}
		scanreq.ScanTypes = keys //TODO:  Do I want to scan everything by default?
	}
	for _, scanType := range scanreq.ScanTypes {
		addrs, err := Hosts(scanreq.Address)
		if err != nil {
			return err
		}
		if len(addrs) > 0 { //Generate lots of scan objects as we're scanning a subnet
			for _, addr := range addrs {
				var scan scandaloriantypes.Scan
				scan.RequestID = id
				scan.ScanID = uuid.New().String()
				scan.IP = addr
				scan.Stream = streams[scanType]
				log.Infof("Sending to topic: %s", scan.Stream)
				err = messageBus.Publish(&scan)
				if err != nil {
					log.Warn(err)
					return err
				}
			}
			return nil
		}
		var scan scandaloriantypes.Scan
		scan.RequestID = id
		scan.ScanID = uuid.New().String()
		scan.IP = scanreq.Address
		scan.Stream = streams[scanType]
		log.Infof("Sending to topic: %s", scan.Stream)
		err = messageBus.Publish(&scan)
		if err != nil {
			log.Warn(err)
			return err
		}

	}
	return nil
}

//Hosts split cidr into individual IP addresses
func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
