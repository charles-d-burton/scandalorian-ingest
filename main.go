package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	scandaloriantypes "github.com/charles-d-burton/scandalorian-types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(scan scandaloriantypes.Scan) error
	Close()
}

type ConfigSpec struct {
	LogLevel string
	BusHost  string `required:"true"`
	Port     string `required:"true"`
}

func main() {
	log.Info().Msg("Starting up")
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	var cs ConfigSpec
	err := envconfig.Process("ingest", &cs)
	log.Info().Msgf("connecting to: %v:%v", cs.BusHost, cs.Port)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	bus, err := connectBus(&cs)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	defer bus.Close()
	router := gin.Default()
	router.POST("/scan", handlePost(bus))
	router.Run(":9090")
}

//Connect to a message bus, this is abstracted to an interface so implementations of other busses e.g. Rabbit are easier
func connectBus(cs *ConfigSpec) (MessageBus, error) {
	var bus MessageBus
	if strings.Contains(cs.BusHost, "nats") {
		var nats NatsConn
		bus = &nats
		err := nats.Connect(cs.BusHost, cs.Port)
		if err != nil {
			return nil, err
		}
		bus = &nats
	} else {
		return nil, errors.New("only valid protocol is nats://")
	}
	return bus, nil
}

func handlePost(bus MessageBus) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		var scanRequest scandaloriantypes.ScanRequest
		if err := c.ShouldBindJSON(&scanRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if scanRequest.Host == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "must set host"})
		} else if strings.Contains(strings.ToLower(scanRequest.Host), "localhost") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot scan localhost"})
		} else {
			if !isIPAddr(scanRequest.Host) {
				log.Debug().Msgf("host is hostname not IP: %v", scanRequest.Host)
				domain, err := getHostDomain(scanRequest.Host)
				if err != nil || domain == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				}
				addr, err := net.LookupIP(scanRequest.Host)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "unknown host"})
					return
				}
				fmt.Println("IP address: ", addr)
				for _, address := range addr {
					scanRequest.Host = address.String()
					scanRequest.FQDN = domain
					if err := enQueueRequest(&scanRequest, bus); err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
						return
					}
				}
			} else {
				parts := strings.Split(scanRequest.Host, "/") //Check for CIDR notation
				if len(parts) < 2 {
					scanRequest.Host = scanRequest.Host + "/32"
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
				ip, _, err := net.ParseCIDR(scanRequest.Host)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				if ip.IsLoopback() {
					c.JSON(http.StatusBadRequest, gin.H{"error": "cannot scan loopback"})
					return
				}
				if err := enQueueRequest(&scanRequest, bus); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			}
		}
	}
	return gin.HandlerFunc(fn)
}

func enQueueRequest(scanreq *scandaloriantypes.ScanRequest, bus MessageBus) error {
	id := uuid.New().String()
	if scanreq.PortScan != nil || scanreq.ApplicationScan != nil {
		addrs, err := Hosts(scanreq.Host)
		if err != nil {
			return err
		}
		if len(addrs) > 0 { //Generate lots of scan objects as we're scanning a subnet
			for _, addr := range addrs {
				var scanMeta scandaloriantypes.ScanMetaData
				scanMeta.RequestID = id
				scanMeta.IP = addr
				if scanreq.PortScan != nil && scanreq.PortScan.Run {
					scanreq.PortScan.SetDefaults(&scanMeta)
					setPorts(scanreq)
					log.Debug().Msgf("sending to topic: %s", scanreq.PortScan.GetStream())
					err = bus.Publish(scanreq.PortScan)
					if err != nil {
						return err
					}
				}
				if scanreq.ApplicationScan != nil && scanreq.ApplicationScan.Run {
					log.Debug().Msg("called application scan")
					//TODO Implement
				}

			}
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

func isIPAddr(host string) bool {
	addr := net.ParseIP(host)
	if addr != nil {
		return true
	}
	return false
}

func getHostDomain(host string) (domain string, err error) {
	u, err := url.ParseRequestURI(host)
	if err != nil {
		u, repErr := url.ParseRequestURI("https://" + host)
		if repErr != nil {
			return "", errors.New(fmt.Sprintf("invalid host: %v", host))
		}
		return u.Host, nil
	}
	return u.Host, nil
}

func setPorts(scanreq *scandaloriantypes.ScanRequest) {
	if scanreq.PortScan.TopTen || scanreq.PortScan.TopHundred || scanreq.PortScan.TopThousand {
		if scanreq.PortScan.TopTen {
			scanreq.PortScan.Ports = generatePortList(top10Ports)
		}
		if scanreq.PortScan.TopHundred {
			scanreq.PortScan.Ports = generatePortList(top100Ports)
		}
		if scanreq.PortScan.TopThousand {
			scanreq.PortScan.Ports = generatePortList(top1000Ports)
		}
	} else {
		for i := 0; i <= 65535; i++ {
			scanreq.PortScan.Ports = append(scanreq.PortScan.Ports, i)
		}
	}
}

//generatePortList corrects port ranges and deduplicates port list
func generatePortList(ports []string) []int {
	set := make(map[int]struct{}) //set with zero byte value
	var exists = struct{}{}       //zero byte structure
	for _, port := range ports {
		if strings.Contains(port, "-") {
			for _, p := range expandPortRange(port) {
				set[p] = exists
			}
			continue
		}
		p, _ := strconv.Atoi(port)
		set[p] = exists
	}
	newPorts := make([]int, len(set))
	for key := range set {
		newPorts = append(newPorts, key)
	}
	return newPorts
}

//Expand port ranges
func expandPortRange(portRange string) []int {
	ports := strings.Split(portRange, "-")
	begin, _ := strconv.Atoi(ports[0])
	end, _ := strconv.Atoi(ports[1])
	portList := make([]int, end-begin)
	for i := begin; i <= end; i++ {
		portList = append(portList, i)
	}
	return portList
}
