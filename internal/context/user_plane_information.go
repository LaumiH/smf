package context

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sort"
	"sync"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
	"github.com/google/uuid"
)

// UserPlaneInformation store userplane topology
type UserPlaneInformation struct {
	Mu sync.RWMutex // protect UPF and topology structure

	NameToUPNode              map[string]UPNodeInterface      // map name to UPNode (AN and UPF)
	UPFs                      map[uuid.UUID]*UPF              // map UUID to UPF
	NodeIDToUPF               map[string]*UPF                 // map NodeID (IP or FQDN) to UPF
	NodeIDToName              map[string]string               // map NodeID (IP or FQDN) to name
	DefaultUserPlanePath      map[string]UPPath               // DNN to Default Path
	DefaultUserPlanePathToUPF map[string]map[uuid.UUID]UPPath // DNN to UPF UUID to Default Path
	AccessNetwork             map[string]UPNodeInterface      // map name to UPNode (only AN)
}

type UPNodeType string

const (
	UPNODE_UPF UPNodeType = "UPF"
	UPNODE_AN  UPNodeType = "AN"
)

// UPNode represent the user plane node topology
type UPNode struct {
	Name   string
	Type   UPNodeType
	ID     uuid.UUID
	NodeID pfcpType.NodeID
	Dnn    string
	Links  UPPath
	//UPF    *UPF
}

type UPNodeInterface interface {
	String() string
	GetName() string
	GetID() uuid.UUID
	GetType() UPNodeType
	GetLinks() UPPath
	AddLink(link UPNodeInterface) bool
	RemoveLink(link UPNodeInterface) bool
	NodeIDToString() string
}

type GNB struct {
	UPNode
	ANIP net.IP
}

func (gNB *GNB) GetName() string {
	return gNB.Name
}

func (gNB *GNB) GetID() uuid.UUID {
	return gNB.ID
}

func (gNB *GNB) GetType() UPNodeType {
	return gNB.Type
}

func (gNB *GNB) String() string {
	str := "gNB {\n"
	prefix := "  "
	str += prefix + fmt.Sprintf("Name: %s\n", gNB.Name)
	str += prefix + fmt.Sprintf("ANIP: %s\n", gNB.ANIP)
	str += prefix + fmt.Sprintf("ID: %s\n", gNB.ID)
	str += prefix + fmt.Sprintf("NodeID: %s\n", gNB.NodeIDToString())
	str += prefix + fmt.Sprintf("Dnn: %s\n", gNB.Dnn)
	str += prefix + fmt.Sprintln("Links:")
	for _, link := range gNB.Links {
		str += prefix + fmt.Sprintf("-- %s: %s\n", link.GetName(), link.NodeIDToString())
	}
	str += "}"
	return str
}

func (gNB *GNB) NodeIDToString() string {
	switch gNB.NodeID.NodeIdType {
	case pfcpType.NodeIdTypeIpv4Address, pfcpType.NodeIdTypeIpv6Address:
		return gNB.NodeID.IP.String()
	case pfcpType.NodeIdTypeFqdn:
		return gNB.NodeID.FQDN
	default:
		logger.CtxLog.Errorf("nodeID has unknown type %d", gNB.NodeID.NodeIdType)
		return ""
	}
}

func (gNB *GNB) GetLinks() UPPath {
	return gNB.Links
}

func (gNB *GNB) AddLink(link UPNodeInterface) bool {
	for _, existingLink := range gNB.Links {
		if link.GetName() == existingLink.GetName() {
			logger.CfgLog.Warningf("UPLink [%s] <=> [%s] already exists, skip\n", existingLink.GetName(), link.GetName())
			return false
		}
	}
	gNB.Links = append(gNB.Links, link)
	return true
}

func (gNB *GNB) RemoveLink(link UPNodeInterface) bool {
	for i, existingLink := range gNB.Links {
		if link.GetName() == existingLink.GetName() && existingLink.NodeIDToString() == link.NodeIDToString() {
			logger.CfgLog.Warningf("Remove UPLink [%s] <=> [%s]\n", existingLink.GetName(), link.GetName())
			gNB.Links = append(gNB.Links[:i], gNB.Links[i+1:]...)
			return true
		}
	}
	return false
}

// UPPath represents the User Plane Node Sequence of this path
type UPPath []UPNodeInterface

func (upPath UPPath) String() string {
	str := ""
	for i, upNode := range upPath {
		str += fmt.Sprintf("Node %d: %s", i, upNode)
	}
	return str
}

func (upPath UPPath) NodeInPath(upNode UPNodeInterface) int {
	for i, u := range upPath {
		if u == upNode {
			return i
		}
	}
	return -1
}

/*func AllocateUPFID() {
	UPFsID := smfContext.UserPlaneInformation.UPFsID
	UPFsIPtoID := smfContext.UserPlaneInformation.UPFsIPtoID

	for upfName, upfNode := range smfContext.UserPlaneInformation.UPFs {
		upfid := upfNode.UPF.UUID()
		upfip := upfNode.NodeID.ResolveNodeIdToIp().String()

		UPFsID[upfName] = upfid
		UPFsIPtoID[upfip] = upfid
	}
}*/

// the config has a single string for NodeID,
// check its nature and create either IPv4, IPv6, or FQDN NodeID type
func ConfigToNodeID(configNodeID string) pfcpType.NodeID {
	var ip net.IP
	if net.ParseIP(configNodeID).To4() == nil {
		ip = net.ParseIP(configNodeID)
	} else {
		ip = net.ParseIP(configNodeID).To4()
	}
	switch len(configNodeID) {
	case net.IPv4len:
		return pfcpType.NodeID{
			NodeIdType: pfcpType.NodeIdTypeIpv4Address,
			IP:         ip,
		}
	case net.IPv6len:
		return pfcpType.NodeID{
			NodeIdType: pfcpType.NodeIdTypeIpv6Address,
			IP:         ip,
		}
	default:
		return pfcpType.NodeID{
			NodeIdType: pfcpType.NodeIdTypeFqdn,
			FQDN:       configNodeID,
		}
	}
}

// NewUserPlaneInformation processes the configuration then returns a new instance of UserPlaneInformation
func NewUserPlaneInformation(upTopology *factory.UserPlaneInformation) (upi *UserPlaneInformation) {
	allUEIPPools := []*UeIPPool{}

	upi = &UserPlaneInformation{
		NameToUPNode:              make(map[string]UPNodeInterface),
		UPFs:                      make(map[uuid.UUID]*UPF),
		NodeIDToUPF:               make(map[string]*UPF),
		NodeIDToName:              make(map[string]string),
		AccessNetwork:             make(map[string]UPNodeInterface),
		DefaultUserPlanePath:      make(map[string]UPPath),
		DefaultUserPlanePathToUPF: make(map[string]map[uuid.UUID]UPPath),
	}

	// name = dictionary object name in yaml
	for name, node := range upTopology.UPNodes {
		upNode := &UPNode{
			Name:   name,
			Type:   UPNodeType(node.Type),
			ID:     uuid.New(),
			NodeID: ConfigToNodeID(node.NodeID),
			Dnn:    node.Dnn,
		}

		switch upNode.Type {
		case UPNODE_AN:
			gNB := &GNB{
				UPNode: *upNode,
				ANIP:   ConfigToNodeID(node.NodeID).IP,
			}
			upi.NameToUPNode[name] = gNB
			upi.AccessNetwork[name] = gNB
			upi.NodeIDToName[gNB.NodeIDToString()] = name
		case UPNODE_UPF:
			upf := NewUPF(upNode, node.InterfaceUpfInfoList, node.SNssaiInfos)
			upi.NameToUPNode[name] = upf
			upi.UPFs[upf.ID] = upf
			upi.NodeIDToUPF[upf.NodeIDToString()] = upf
			upi.NodeIDToName[upf.NodeIDToString()] = name

			// collect IP pool of this UPF for later overlap check
			for _, sNssaiInfo := range upf.SNssaiInfos {
				for _, dnnUPFInfo := range sNssaiInfo.DnnList {
					allUEIPPools = append(allUEIPPools, dnnUPFInfo.UeIPPools...)
				}
			}
		default:
			logger.InitLog.Warningf("invalid UPNodeType: %s\n", upNode.Type)
		}
	}

	if isOverlap(allUEIPPools) {
		logger.InitLog.Fatalf("overlap cidr value between UPFs")
	}

	for _, link := range upTopology.Links {
		nodeA := upi.NameToUPNode[link.A]
		nodeB := upi.NameToUPNode[link.B]

		if nodeA == nil || nodeB == nil {
			logger.CfgLog.Warningf("One of link edges does not exist. UPLink [%s] <=> [%s] not established\n", link.A, link.B)
			continue
		}

		nodeA.AddLink(nodeB)
		nodeB.AddLink(nodeA)
	}

	return upi
}

func (upi *UserPlaneInformation) UpNodesToConfiguration() map[string]*factory.UPNode {
	nodes := make(map[string]*factory.UPNode)
	for name, upNode := range upi.NameToUPNode {
		node := &factory.UPNode{
			NodeID: upNode.NodeIDToString(),
		}

		switch upNode.GetType() {
		case UPNODE_AN:
			node.Type = "AN"
		case UPNODE_UPF:
			node.Type = "UPF"
			upf := upNode.(*UPF)
			if upf.SNssaiInfos != nil {
				FsNssaiInfoList := make([]*factory.SnssaiUpfInfoItem, 0)
				for _, sNssaiInfo := range upf.SNssaiInfos {
					FDnnUpfInfoList := make([]*factory.DnnUpfInfoItem, 0)
					for _, dnnInfo := range sNssaiInfo.DnnList {
						FUEIPPools := make([]*factory.UEIPPool, 0)
						FStaticUEIPPools := make([]*factory.UEIPPool, 0)
						for _, pool := range dnnInfo.UeIPPools {
							FUEIPPools = append(FUEIPPools, &factory.UEIPPool{
								Cidr: pool.ueSubNet.String(),
							})
						} // for pool
						for _, pool := range dnnInfo.StaticIPPools {
							FStaticUEIPPools = append(FStaticUEIPPools, &factory.UEIPPool{
								Cidr: pool.ueSubNet.String(),
							})
						} // for static pool
						FDnnUpfInfoList = append(FDnnUpfInfoList, &factory.DnnUpfInfoItem{
							Dnn:         dnnInfo.Dnn,
							Pools:       FUEIPPools,
							StaticPools: FStaticUEIPPools,
						})
					} // for dnnInfo
					Fsnssai := &factory.SnssaiUpfInfoItem{
						SNssai: &models.Snssai{
							Sst: sNssaiInfo.SNssai.Sst,
							Sd:  sNssaiInfo.SNssai.Sd,
						},
						DnnUpfInfoList: FDnnUpfInfoList,
					}
					FsNssaiInfoList = append(FsNssaiInfoList, Fsnssai)
				} // for sNssaiInfo
				node.SNssaiInfos = FsNssaiInfoList
			} // if UPF.SNssaiInfos

			FNxList := make([]*factory.InterfaceUpfInfoItem, 0)
			for _, iface := range upf.N3Interfaces {
				endpoints := make([]string, 0)
				// upf.go L90
				if iface.EndpointFQDN != "" {
					endpoints = append(endpoints, iface.EndpointFQDN)
				}
				for _, eIP := range iface.IPv4EndPointAddresses {
					endpoints = append(endpoints, eIP.String())
				}
				FNxList = append(FNxList, &factory.InterfaceUpfInfoItem{
					InterfaceType:    models.UpInterfaceType_N3,
					Endpoints:        endpoints,
					NetworkInstances: iface.NetworkInstances,
				})
			} // for N3Interfaces

			for _, iface := range upf.N9Interfaces {
				endpoints := make([]string, 0)
				// upf.go L90
				if iface.EndpointFQDN != "" {
					endpoints = append(endpoints, iface.EndpointFQDN)
				}
				for _, eIP := range iface.IPv4EndPointAddresses {
					endpoints = append(endpoints, eIP.String())
				}
				FNxList = append(FNxList, &factory.InterfaceUpfInfoItem{
					InterfaceType:    models.UpInterfaceType_N9,
					Endpoints:        endpoints,
					NetworkInstances: iface.NetworkInstances,
				})
			} // N9Interfaces
			node.InterfaceUpfInfoList = FNxList
		default:
			node.Type = "Unknown"
		}

		nodes[name] = node
	}

	return nodes
}

func (upi *UserPlaneInformation) LinksToConfiguration() []*factory.UPLink {
	links := make([]*factory.UPLink, 0)
	source, err := upi.selectUPPathSource()
	if err != nil {
		logger.InitLog.Errorf("AN Node not found\n")
	} else {
		visited := make(map[UPNodeInterface]bool)
		queue := make(UPPath, 0)
		queue = append(queue, source)
		for {
			node := queue[0]
			queue = queue[1:]
			visited[node] = true
			for _, link := range node.GetLinks() {
				if !visited[link] {
					queue = append(queue, link)
					nodeIdA := node.NodeIDToString()
					nodeIdB := link.NodeIDToString()
					linkA := upi.NodeIDToName[nodeIdA]
					linkB := upi.NodeIDToName[nodeIdB]
					links = append(links, &factory.UPLink{

						A: linkA,
						B: linkB,
					})
				}
			}
			if len(queue) == 0 {
				break
			}
		}
	}
	return links
}

func (upi *UserPlaneInformation) UpNodesFromConfiguration(upTopology *factory.UserPlaneInformation) {
	allUEIPPools := []*UeIPPool{}

	for name, node := range upTopology.UPNodes {
		if _, ok := upi.NameToUPNode[name]; ok {
			logger.InitLog.Warningf("Node [%s] already exists in SMF.\n", name)
			continue
		}
		upNode := &UPNode{
			Name:   name,
			Type:   UPNodeType(node.Type),
			ID:     uuid.New(),
			NodeID: ConfigToNodeID(node.NodeID),
			Dnn:    node.Dnn,
		}

		switch upNode.Type {
		case UPNODE_AN:
			gNB := &GNB{
				UPNode: *upNode,
			}
			upi.NameToUPNode[name] = gNB
			upi.AccessNetwork[name] = gNB
			upi.NodeIDToName[gNB.NodeIDToString()] = name
		case UPNODE_UPF:
			upf := NewUPF(upNode, node.InterfaceUpfInfoList, node.SNssaiInfos)
			upi.NameToUPNode[name] = upf
			upi.UPFs[upf.ID] = upf
			upi.NodeIDToUPF[upf.NodeIDToString()] = upf
			upi.NodeIDToName[upf.NodeIDToString()] = name

			// collect IP pool of this UPF for later overlap check
			for _, sNssaiInfo := range upf.SNssaiInfos {
				for _, dnnUPFInfo := range sNssaiInfo.DnnList {
					allUEIPPools = append(allUEIPPools, dnnUPFInfo.UeIPPools...)
				}
			}

		default:
			logger.InitLog.Warningf("invalid UPNodeType: %s\n", upNode.Type)
		}
	}

	if isOverlap(allUEIPPools) {
		logger.InitLog.Fatalf("overlap cidr value between UPFs")
	}
}

func (upi *UserPlaneInformation) LinksFromConfiguration(upTopology *factory.UserPlaneInformation) {
	for _, link := range upTopology.Links {
		nodeA := upi.NameToUPNode[link.A]
		nodeB := upi.NameToUPNode[link.B]

		if nodeA == nil || nodeB == nil {
			logger.CfgLog.Warningf("One of link edges does not exist. UPLink [%s] <=> [%s] not established\n", link.A, link.B)
			continue
		}

		nodeA.AddLink(nodeB)
		nodeB.AddLink(nodeA)
	}
}

// *** add unit test ***//
func (upi *UserPlaneInformation) GetUPFNodeByNodeID(nodeID pfcpType.NodeID) *UPF {
	for id, upf := range upi.NodeIDToUPF {
		if id == nodeID.ResolveNodeIdToIp().String() {
			return upf
		}
	}
	logger.CtxLog.Errorf("Could not find UPF with NodeID %s", nodeID.ResolveNodeIdToIp().String())
	return nil
}

// *** add unit test ***//
func (upi *UserPlaneInformation) RemoveUPFNodeByNodeID(nodeID pfcpType.NodeID) bool {
	id := nodeID.ResolveNodeIdToIp().String()
	uuid := upi.NodeIDToUPF[id].ID
	name := upi.NodeIDToName[id]

	delete(upi.NodeIDToName, id)
	delete(upi.NodeIDToUPF, id)
	delete(upi.UPFs, uuid)
	delete(upi.NameToUPNode, name)

	return true
}

func (upi *UserPlaneInformation) GetUpfById(uuid uuid.UUID) *UPF {
	return upi.UPFs[uuid]
}

func (upi *UserPlaneInformation) UpNodeDelete(name string) {
	if toDelete := upi.NameToUPNode[name]; toDelete != nil {
		logger.InitLog.Infof("UPNode [%s] found. Deleting it.\n", name)
		id := toDelete.NodeIDToString()
		delete(upi.NodeIDToName, id)
		delete(upi.NameToUPNode, name)

		if toDelete.GetType() == UPNODE_AN {
			delete(upi.AccessNetwork, name)
		}

		if toDelete.GetType() == UPNODE_UPF {
			uuid := toDelete.(*UPF).ID
			delete(upi.NodeIDToUPF, id)
			delete(upi.UPFs, uuid)
		}

		for dnn, destMap := range upi.DefaultUserPlanePathToUPF {
			for uuid, path := range destMap {
				if path.NodeInPath(toDelete) != -1 {
					logger.InitLog.Infof("Invalidate cache entry: DefaultUserPlanePathToUPF[%s][%s].\n", dnn, uuid)
					delete(upi.DefaultUserPlanePathToUPF[dnn], uuid)
				}
			}
		}
		for dnn, path := range upi.DefaultUserPlanePath {
			if path.NodeInPath(toDelete) != -1 {
				logger.InitLog.Infof("Invalidate cache entry: DefaultUserPlanePath[%s].\n", dnn)
				delete(upi.DefaultUserPlanePath, dnn)
			}
		}

		// update links
		for _, node := range upi.NameToUPNode {
			node.RemoveLink(toDelete)
		}

	} else {
		logger.CtxLog.Infof("UPNode [%s] NOT found.\n", name)
	}
}

func (upi *UserPlaneInformation) GetDefaultUserPlanePathByDNN(selection *UPFSelectionParams) (path UPPath) {
	path, pathExist := upi.DefaultUserPlanePath[selection.String()]
	logger.CtxLog.Traceln("In GetDefaultUserPlanePathByDNN")
	logger.CtxLog.Traceln("selection: ", selection.String())
	if pathExist {
		return
	} else {
		pathExist = upi.GenerateDefaultPath(selection)
		if pathExist {
			return upi.DefaultUserPlanePath[selection.String()]
		}
	}
	return nil
}

func (upi *UserPlaneInformation) GetDefaultUserPlanePathByDNNAndUPF(
	selection *UPFSelectionParams,
	upf *UPF,
) (path UPPath) {
	uuid := upf.ID

	if upi.DefaultUserPlanePathToUPF[selection.String()] != nil {
		if path, pathExists := upi.DefaultUserPlanePathToUPF[selection.String()][uuid]; pathExists {
			logger.CtxLog.Debugf("Existing default UPPath for DNN %s and UPF[%s]", selection.String(), upf.NodeIDToString())
			return path
		}
	}

	logger.CtxLog.Debugf("Create new default UPPath for DNN %s and UPF[%s]", selection.String(), upf.NodeIDToString())
	if path, err := upi.GenerateDefaultPathToUPF(selection, upf); err != nil {
		logger.CtxLog.Errorln("Failed to create new default UPPath: ", err)
		return nil
	} else {
		return path
	}

}

func (upi *UserPlaneInformation) ExistDefaultPath(dnn string) bool {
	_, exist := upi.DefaultUserPlanePath[dnn]
	return exist
}

func GenerateDataPath(upPath UPPath) *DataPath {
	logger.CtxLog.Tracef("[GenerateDataPath] Generating data path for UPPath %s\n", upPath.String())

	if len(upPath) < 1 {
		logger.CtxLog.Errorf("Invalid data path")
		return nil
	}
	lowerBound := 0
	upperBound := len(upPath) - 1
	var root *DataPathNode
	var node *DataPathNode
	var prevDataPathNode *DataPathNode

	for idx, upNode := range upPath {
		node = NewDataPathNode()
		if upNode.GetType() == UPNODE_UPF {
			node.UPF = upNode.(*UPF)
		}

		if idx == lowerBound {
			root = node
			root.AddPrev(nil)
		}
		if idx == upperBound {
			node.AddNext(nil)
		}
		if prevDataPathNode != nil {
			prevDataPathNode.AddNext(node)
			node.AddPrev(prevDataPathNode)
		}
		prevDataPathNode = node
	}

	dataPath := NewDataPath()
	dataPath.FirstDPNode = root
	return dataPath
}

func (upi *UserPlaneInformation) GenerateDefaultPath(selection *UPFSelectionParams) bool {
	var source UPNodeInterface
	var destinations UPPath

	for _, node := range upi.AccessNetwork {
		if node.GetType() == UPNODE_AN {
			source = node
			break
		}
	}

	if source == nil {
		logger.CtxLog.Errorf("There is no AN Node in config file!")
		return false
	}

	destinations = upi.selectMatchUPF(selection)

	if len(destinations) == 0 {
		logger.CtxLog.Errorf("Can't find UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
		return false
	} else {
		logger.CtxLog.Tracef("Found UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]\n", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
	}

	// Run DFS
	visited := make(map[UPNodeInterface]bool)

	for _, upNode := range upi.NameToUPNode {
		visited[upNode] = false
	}

	path, pathExist := getPathBetween(source, destinations[0], visited, selection)

	if pathExist {
		if path[0].GetType() == UPNODE_AN {
			path = path[1:]
		}
		upi.DefaultUserPlanePath[selection.String()] = path
	}

	return pathExist
}

func (upi *UserPlaneInformation) GenerateDefaultPathToUPF(selection *UPFSelectionParams, destination *UPF) (UPPath, error) {
	var source UPNodeInterface

	for _, node := range upi.AccessNetwork {
		if node.GetType() == UPNODE_AN {
			source = node
			break
		}
	}

	if source == nil {
		return nil, fmt.Errorf("there is no AN node in the SMF config file")
	}

	// Run DFS
	visited := make(map[UPNodeInterface]bool)

	for _, upNode := range upi.NameToUPNode {
		visited[upNode] = false
	}

	if path, success := getPathBetween(source, destination, visited, selection); success {
		if path[0].GetType() == UPNODE_AN {
			path = path[1:]
		}
		if upi.DefaultUserPlanePathToUPF[selection.String()] == nil {
			upi.DefaultUserPlanePathToUPF[selection.String()] = make(map[uuid.UUID]UPPath)
		}
		upi.DefaultUserPlanePathToUPF[selection.String()][destination.GetID()] = path
		return path, nil
	} else {
		return nil, fmt.Errorf("failed to generate path between src: %s and dst: %s", source.GetName(), destination.GetName())
	}
}

func (upi *UserPlaneInformation) selectMatchUPF(selection *UPFSelectionParams) UPPath {
	upList := make(UPPath, 0)

	for _, upNode := range upi.NameToUPNode {
		if upNode.GetType() == UPNODE_UPF {
			for _, snssaiInfo := range upNode.(*UPF).SNssaiInfos {
				currentSnssai := snssaiInfo.SNssai
				targetSnssai := selection.SNssai

				if currentSnssai.Equal(targetSnssai) {
					for _, dnnInfo := range snssaiInfo.DnnList {
						if dnnInfo.Dnn == selection.Dnn && dnnInfo.ContainsDNAI(selection.Dnai) {
							upList = append(upList, upNode)
							break
						}
					}
				}
			}
		}
	}
	return upList
}

func getPathBetween(cur UPNodeInterface, dest UPNodeInterface, visited map[UPNodeInterface]bool,
	selection *UPFSelectionParams,
) (path UPPath, pathExist bool) {
	visited[cur] = true

	if reflect.DeepEqual(cur, dest) {
		path = make(UPPath, 0)
		path = append(path, cur)
		pathExist = true
		return path, pathExist
	}

	selectedSNssai := selection.SNssai

	for _, node := range cur.GetLinks() {
		if !visited[node] {
			if node.GetType() == UPNODE_UPF && !node.(*UPF).isSupportSnssai(selectedSNssai) {
				visited[node] = true
				continue
			}

			path_tail, pathExist := getPathBetween(node, dest, visited, selection)

			if pathExist {
				path = make(UPPath, 0)
				path = append(path, cur)
				path = append(path, path_tail...)

				return path, pathExist
			}
		}
	}

	return nil, false
}

// this function select PSA by SNSSAI, DNN and DNAI exlude IP
func (upi *UserPlaneInformation) selectAnchorUPF(source UPNodeInterface, selection *UPFSelectionParams) []*UPF {
	// UPFSelectionParams may have static IP, but we would not match static IP in "MatchedSelection" function
	upfList := make([]*UPF, 0)
	visited := make(map[UPNodeInterface]bool)
	queue := make([]UPNodeInterface, 0)
	selectionForIUPF := &UPFSelectionParams{
		Dnn:    selection.Dnn,
		SNssai: selection.SNssai,
	}

	queue = append(queue, source)
	for {
		node := queue[0]
		queue = queue[1:]
		findNewNode := false
		visited[node] = true
		for _, link := range node.GetLinks() {
			if !visited[link] {
				if link.GetType() == UPNODE_UPF && link.(*UPF).MatchedSelection(selectionForIUPF) {
					queue = append(queue, link)
					findNewNode = true
					break
				}
			}
		}
		if !findNewNode {
			// if new node is AN type not need to add upList
			if node.GetType() == UPNODE_UPF && node.(*UPF).MatchedSelection(selection) {
				upfList = append(upfList, node.(*UPF))
			}
		}

		if len(queue) == 0 {
			break
		}
	}
	return upfList
}

func (upi *UserPlaneInformation) sortUPFListByName(upfList []*UPF) []*UPF {
	names := make([]string, 0, len(upi.NameToUPNode))

	for name, node := range upi.NameToUPNode {
		if node.GetType() == UPNODE_AN {
			continue
		}
		names = append(names, name)
	}

	sort.Strings(names)

	sortedUpList := make([]*UPF, 0)
	for _, name := range names {
		sortedUpList = append(sortedUpList, upi.NameToUPNode[name].(*UPF))
	}

	return sortedUpList
}

func (upi *UserPlaneInformation) selectUPPathSource() (UPNodeInterface, error) {
	// if multiple gNBs exist, select one according to some criterion
	for _, node := range upi.AccessNetwork {
		if node.GetType() == UPNODE_AN {
			return node, nil
		}
	}
	return nil, errors.New("AN Node not found")
}

// SelectUPFAndAllocUEIP will return PSA UPF, allocated UE IP and use/not use static IP
func (upi *UserPlaneInformation) SelectUPFAndAllocUEIP(selection *UPFSelectionParams) (*UPF, net.IP, bool, error) {
	source, err := upi.selectUPPathSource()
	if err != nil {
		return nil, nil, false, err
	}
	psaCandidates := upi.selectAnchorUPF(source, selection) //select candidates for the PSA UPF
	if len(psaCandidates) == 0 {
		return nil, nil, false, fmt.Errorf("cannot find suitable PSA UPF for selection params %+v", selection)
	}

	psaCandidates = upi.sortUPFListByName(psaCandidates)

	if len(psaCandidates) == 0 {
		return nil, nil, false, fmt.Errorf("PSA candidates is empty after sorting")
	}

	sortedUPFList := createUPFListForSelection(psaCandidates)
	var selectedPSA *UPF

	for _, upf := range sortedUPFList {
		logger.CtxLog.Debugf("Check candiate PSA UPF[%s] and its secondary UPF", upf.NodeIDToString())
		select {
		case <-upf.Association.Done():
			logger.CtxLog.Warnf("Primary UPF[%s] is not associated, do not select as PSA", upf.NodeIDToString())
		default:
			selectedPSA = upf
		}

		IPPools, useStaticIPPool := getUEIPPool(upf, selection)
		if len(IPPools) == 0 {
			logger.CtxLog.Warnf("IP pool exhausted for candidate UPF[%s]", selectedPSA.NodeIDToString())
			continue
		}
		sortedIPPoolList := createPoolListForSelection(IPPools)
		for _, pool := range sortedIPPoolList {
			logger.CtxLog.Debugf("check UEIPPool(%+v)", pool.ueSubNet)
			ueIP := pool.allocate(selection.PDUAddress)
			if ueIP != nil {
				logger.CtxLog.Infof("Selected PSA UPF[%s] and UE IP [%s]", selectedPSA.NodeIDToString(), ueIP.String())
				return upf, ueIP, useStaticIPPool, nil
			}
			// if all addresses in pool are used, search next pool
			logger.CtxLog.Debug("check next IP pool")
		}
		// if all addresses in UPF are used, search next UPF
		logger.CtxLog.Debug("check next UPF")
	}
	// checked all UPFs
	return nil, nil, false, fmt.Errorf("all PSA UPF IP pools exhausted for selection params %+v", selection)
}

func createUPFListForSelection(inputList []*UPF) (outputList []*UPF) {
	offset := rand.Intn(len(inputList))
	return append(inputList[offset:], inputList[:offset]...)
}

func createPoolListForSelection(inputList []*UeIPPool) (outputList []*UeIPPool) {
	offset := rand.Intn(len(inputList))
	return append(inputList[offset:], inputList[:offset]...)
}

// getUEIPPool will return IP pools and use/not use static IP pool
func getUEIPPool(upf *UPF, selection *UPFSelectionParams) ([]*UeIPPool, bool) {
	for _, snssaiInfo := range upf.SNssaiInfos {
		currentSnssai := snssaiInfo.SNssai
		targetSnssai := selection.SNssai

		if currentSnssai.Equal(targetSnssai) {
			for _, dnnInfo := range snssaiInfo.DnnList {
				if dnnInfo.Dnn == selection.Dnn {
					if selection.Dnai != "" && !dnnInfo.ContainsDNAI(selection.Dnai) {
						continue
					}
					if selection.PDUAddress != nil {
						// return static ue ip pool
						for _, ueIPPool := range dnnInfo.StaticIPPools {
							if ueIPPool.ueSubNet.Contains(selection.PDUAddress) {
								// return match IPPools
								return []*UeIPPool{ueIPPool}, true
							}
						}

						// return dynamic ue ip pool
						for _, ueIPPool := range dnnInfo.UeIPPools {
							if ueIPPool.ueSubNet.Contains(selection.PDUAddress) {
								logger.CfgLog.Infof("cannot find selected IP in static pool[%v], use dynamic pool[%+v]",
									dnnInfo.StaticIPPools, dnnInfo.UeIPPools)
								return []*UeIPPool{ueIPPool}, false
							}
						}

						return nil, false
					}

					// if no specify static PDU Address
					return dnnInfo.UeIPPools, false
				}
			}
		}
	}
	return nil, false
}

func (upi *UserPlaneInformation) ReleaseUEIP(upf *UPF, addr net.IP, static bool) {
	pool := findPoolByAddr(upf, addr, static)
	if pool == nil {
		// nothing to do
		logger.CtxLog.Warnf("Failed to release UE IP address %s of UPF[%s]: pool is empty", addr.String(), upf.NodeIDToString())
		return
	}
	pool.release(addr)
}

func findPoolByAddr(upf *UPF, addr net.IP, static bool) *UeIPPool {
	for _, snssaiInfo := range upf.SNssaiInfos {
		for _, dnnInfo := range snssaiInfo.DnnList {
			if static {
				for _, pool := range dnnInfo.StaticIPPools {
					if pool.ueSubNet.Contains(addr) {
						return pool
					}
				}
			} else {
				for _, pool := range dnnInfo.UeIPPools {
					if pool.ueSubNet.Contains(addr) {
						return pool
					}
				}
			}
		}
	}
	return nil
}
