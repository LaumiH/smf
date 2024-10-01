package context

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/pfcp/pfcpUdp"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
	"github.com/free5gc/util/idgenerator"
)

var upfPool sync.Map

type UPTunnel struct {
	PathIDGenerator *idgenerator.IDGenerator
	DataPathPool    DataPathPool
	ANInformation   struct {
		IPAddress net.IP
		TEID      uint32
	}
}

func (t *UPTunnel) UpdateANInformation(ip net.IP, teid uint32) {
	t.ANInformation.IPAddress = ip
	t.ANInformation.TEID = teid

	for _, dataPath := range t.DataPathPool {
		if dataPath.Activated {
			ANUPF := dataPath.FirstDPNode
			DLPDR := ANUPF.DownLinkTunnel.PDR

			if DLPDR.FAR.ForwardingParameters.OuterHeaderCreation != nil {
				// Old AN tunnel exists
				DLPDR.FAR.ForwardingParameters.SendEndMarker = true
			}

			DLPDR.FAR.ForwardingParameters.OuterHeaderCreation = new(pfcpType.OuterHeaderCreation)
			dlOuterHeaderCreation := DLPDR.FAR.ForwardingParameters.OuterHeaderCreation
			dlOuterHeaderCreation.OuterHeaderCreationDescription = pfcpType.OuterHeaderCreationGtpUUdpIpv4
			dlOuterHeaderCreation.Teid = t.ANInformation.TEID
			dlOuterHeaderCreation.Ipv4Address = t.ANInformation.IPAddress.To4()
			DLPDR.FAR.State = RULE_UPDATE
		}
	}
}

type UPFStatus int

const (
	NotAssociated          UPFStatus = 0
	AssociatedSettingUp    UPFStatus = 1
	AssociatedSetUpSuccess UPFStatus = 2
)

type UPF struct {
	*UPNode

	NodeID pfcpType.NodeID

	UPIPInfo          pfcpType.UserPlaneIPResourceInformation
	UPFStatus         UPFStatus
	RecoveryTimeStamp time.Time

	Ctx        context.Context
	CancelFunc context.CancelFunc

	SNssaiInfos  []*SnssaiUPFInfo
	N3Interfaces []*UPFInterfaceInfo
	N9Interfaces []*UPFInterfaceInfo

	pdrPool sync.Map
	farPool sync.Map
	barPool sync.Map
	qerPool sync.Map
	urrPool sync.Map

	pdrIDGenerator *idgenerator.IDGenerator
	farIDGenerator *idgenerator.IDGenerator
	barIDGenerator *idgenerator.IDGenerator
	urrIDGenerator *idgenerator.IDGenerator
	qerIDGenerator *idgenerator.IDGenerator
}

func (upf *UPF) String() string {
	str := "UPF {\n"
	prefix := "  "
	str += prefix + fmt.Sprintf("Name: %s\n", upf.Name)
	str += prefix + fmt.Sprintf("ID: %s\n", upf.ID)
	str += prefix + fmt.Sprintf("NodeID: %s\n", upf.GetNodeIDString())
	str += prefix + fmt.Sprintln("Links:")
	for _, link := range upf.Links {
		str += prefix + fmt.Sprintf("-- %s: %s\n", link.GetName(), link.GetName())
	}
	str += prefix + fmt.Sprintln("N3 interfaces:")
	for _, iface := range upf.N3Interfaces {
		str += prefix + fmt.Sprintf("-- %s\n", iface)
	}
	if len(upf.N9Interfaces) > 0 {
		str += prefix + fmt.Sprintln("N9 interfaces:")
		for _, iface := range upf.N9Interfaces {
			str += prefix + fmt.Sprintf("-- %s\n", iface)
		}
	}
	str += "}"
	return str
}

// Checks the NodeID type and either returns IPv4, IPv6, or FQDN
func (upf *UPF) GetNodeIDString() string {
	switch upf.NodeID.NodeIdType {
	case pfcpType.NodeIdTypeIpv4Address, pfcpType.NodeIdTypeIpv6Address:
		return upf.NodeID.IP.String()
	case pfcpType.NodeIdTypeFqdn:
		ip := upf.NodeID.ResolveNodeIdToIp()
		return ip.String()
	default:
		logger.CtxLog.Errorf("nodeID has unknown type %d", upf.NodeID.NodeIdType)
		return ""
	}
}

func (upf *UPF) GetNodeID() pfcpType.NodeID {
	return upf.NodeID
}

func (upf *UPF) GetName() string {
	return fmt.Sprintf("%s[%s]", upf.Name, upf.GetNodeIDString())
}

func (upf *UPF) GetID() uuid.UUID {
	return upf.ID
}

func (upf *UPF) GetType() UPNodeType {
	return upf.Type
}

func (upf *UPF) GetLinks() UPPath {
	return upf.Links
}

func (upf *UPF) AddLink(link UPNodeInterface) bool {
	for _, existingLink := range upf.Links {
		if link.GetName() == existingLink.GetName() {
			logger.CfgLog.Warningf("UPLink [%s] <=> [%s] already exists, skip\n", existingLink.GetName(), link.GetName())
			return false
		}
	}
	upf.Links = append(upf.Links, link)
	return true
}

func (upf *UPF) RemoveLink(link UPNodeInterface) bool {
	for i, existingLink := range upf.Links {
		if link.GetName() == existingLink.GetName() && existingLink.GetName() == link.GetName() {
			logger.CfgLog.Warningf("Remove UPLink [%s] <=> [%s]\n", existingLink.GetName(), link.GetName())
			upf.Links = append(upf.Links[:i], upf.Links[i+1:]...)
			return true
		}
	}
	return false
}

func (upf *UPF) RemoveLinkByIndex(index int) bool {
	upf.Links[index] = upf.Links[len(upf.Links)-1]
	return true
}

// UPFSelectionParams ... parameters for upf selection
type UPFSelectionParams struct {
	Dnn        string
	SNssai     *SNssai
	Dnai       string
	PDUAddress net.IP
}

// UPFInterfaceInfo store the UPF interface information
type UPFInterfaceInfo struct {
	NetworkInstances      []string
	IPv4EndPointAddresses []net.IP
	IPv6EndPointAddresses []net.IP
	EndpointFQDN          string
}

func (i *UPFInterfaceInfo) String() string {
	str := ""
	str += fmt.Sprintf("NetworkInstances: %v, ", i.NetworkInstances)
	str += fmt.Sprintf("IPv4EndPointAddresses: %v, ", i.IPv4EndPointAddresses)
	str += fmt.Sprintf("EndpointFQDN: %s", i.EndpointFQDN)
	return str
}

func GetUpfById(uuid string) *UPF {
	upf, ok := upfPool.Load(uuid)
	if ok {
		return upf.(*UPF)
	}
	return nil
}

// NewUPFInterfaceInfo parse the InterfaceUpfInfoItem to generate UPFInterfaceInfo
func NewUPFInterfaceInfo(i *factory.Interface) *UPFInterfaceInfo {
	interfaceInfo := new(UPFInterfaceInfo)

	interfaceInfo.IPv4EndPointAddresses = make([]net.IP, 0)
	interfaceInfo.IPv6EndPointAddresses = make([]net.IP, 0)

	logger.CtxLog.Infoln("Endpoints:", i.Endpoints)

	for _, endpoint := range i.Endpoints {
		eIP := net.ParseIP(endpoint)
		if eIP == nil {
			interfaceInfo.EndpointFQDN = endpoint
		} else if eIPv4 := eIP.To4(); eIPv4 == nil {
			interfaceInfo.IPv6EndPointAddresses = append(interfaceInfo.IPv6EndPointAddresses, eIP)
		} else {
			interfaceInfo.IPv4EndPointAddresses = append(interfaceInfo.IPv4EndPointAddresses, eIPv4)
		}
	}

	interfaceInfo.NetworkInstances = make([]string, len(i.NetworkInstances))
	copy(interfaceInfo.NetworkInstances, i.NetworkInstances)

	return interfaceInfo
}

// *** add unit test ***//
// IP returns the IP of the user plane IP information of the pduSessType
func (i *UPFInterfaceInfo) IP(pduSessType uint8) (net.IP, error) {
	if (pduSessType == nasMessage.PDUSessionTypeIPv4 ||
		pduSessType == nasMessage.PDUSessionTypeIPv4IPv6) && len(i.IPv4EndPointAddresses) != 0 {
		return i.IPv4EndPointAddresses[0], nil
	}

	if (pduSessType == nasMessage.PDUSessionTypeIPv6 ||
		pduSessType == nasMessage.PDUSessionTypeIPv4IPv6) && len(i.IPv6EndPointAddresses) != 0 {
		return i.IPv6EndPointAddresses[0], nil
	}

	if i.EndpointFQDN != "" {
		if resolvedAddr, err := net.ResolveIPAddr("ip", i.EndpointFQDN); err != nil {
			logger.CtxLog.Errorf("resolve addr [%s] failed", i.EndpointFQDN)
		} else {
			if pduSessType == nasMessage.PDUSessionTypeIPv4 {
				return resolvedAddr.IP.To4(), nil
			} else if pduSessType == nasMessage.PDUSessionTypeIPv6 {
				return resolvedAddr.IP.To16(), nil
			} else {
				v4addr := resolvedAddr.IP.To4()
				if v4addr != nil {
					return v4addr, nil
				} else {
					return resolvedAddr.IP.To16(), nil
				}
			}
		}
	}

	return nil, errors.New("not matched ip address")
}

func (upfSelectionParams *UPFSelectionParams) String() string {
	str := "UPFSelectionParams {"
	if upfSelectionParams.Dnn != "" {
		str += fmt.Sprintf("Dnn: %s -- ", upfSelectionParams.Dnn)
	}
	if upfSelectionParams.SNssai != nil {
		str += fmt.Sprintf("Sst: %d, Sd: %s -- ", upfSelectionParams.SNssai.Sst, upfSelectionParams.SNssai.Sd)
	}
	if upfSelectionParams.Dnai != "" {
		str += fmt.Sprintf("DNAI: %s -- ", upfSelectionParams.Dnai)
	}
	if upfSelectionParams.PDUAddress != nil {
		str += fmt.Sprintf("PDUAddress: %s -- ", upfSelectionParams.PDUAddress)
	}
	str += " }"
	return str
}

func NewUPTunnel() (tunnel *UPTunnel) {
	tunnel = &UPTunnel{
		DataPathPool:    make(DataPathPool),
		PathIDGenerator: idgenerator.NewGenerator(1, 2147483647),
	}

	return
}

// *** add unit test ***//
func (t *UPTunnel) AddDataPath(dataPath *DataPath) {
	pathID, err := t.PathIDGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Warnf("Allocate pathID error: %+v", err)
		return
	}

	dataPath.PathID = pathID
	t.DataPathPool[pathID] = dataPath
}

func (t *UPTunnel) RemoveDataPath(pathID int64) {
	delete(t.DataPathPool, pathID)
	t.PathIDGenerator.FreeID(pathID)
}

// *** add unit test ***//
// NewUPF returns a new UPF context in SMF
func NewUPF(
	upNode *UPNode,
	nodeID *pfcpType.NodeID,
	ifaces []*factory.Interface,
) (upf *UPF) {
	upf = new(UPF)
	upf.UPNode = upNode

	upfPool.Store(upf.GetID(), upf)

	// Initialize context
	upf.UPFStatus = NotAssociated
	upf.pdrIDGenerator = idgenerator.NewGenerator(1, math.MaxUint16)
	upf.farIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
	upf.barIDGenerator = idgenerator.NewGenerator(1, math.MaxUint8)
	upf.qerIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
	upf.urrIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)

	upf.N3Interfaces = make([]*UPFInterfaceInfo, 0)
	upf.N9Interfaces = make([]*UPFInterfaceInfo, 0)

	for _, iface := range ifaces {
		upIface := NewUPFInterfaceInfo(iface)

		switch iface.InterfaceType {
		case models.UpInterfaceType_N3:
			upf.N3Interfaces = append(upf.N3Interfaces, upIface)
		case models.UpInterfaceType_N9:
			upf.N9Interfaces = append(upf.N9Interfaces, upIface)
		}
	}

	return upf
}

// *** add unit test ***//
// GetInterface return the UPFInterfaceInfo that match input cond
func (upf *UPF) GetInterface(interfaceType models.UpInterfaceType, dnn string) *UPFInterfaceInfo {
	switch interfaceType {
	case models.UpInterfaceType_N3:
		for i, iface := range upf.N3Interfaces {
			for _, nwInst := range iface.NetworkInstances {
				if nwInst == dnn {
					return upf.N3Interfaces[i]
				}
			}
		}
	case models.UpInterfaceType_N9:
		for i, iface := range upf.N9Interfaces {
			for _, nwInst := range iface.NetworkInstances {
				if nwInst == dnn {
					return upf.N9Interfaces[i]
				}
			}
		}
	}
	return nil
}

func (upf *UPF) PFCPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   upf.NodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}
}

// *** add unit test ***//
func RetrieveUPFNodeByNodeID(nodeID pfcpType.NodeID) *UPF {
	var targetUPF *UPF = nil
	upfPool.Range(func(key, value interface{}) bool {
		curUPF := value.(*UPF)
		if curUPF.NodeID.NodeIdType != nodeID.NodeIdType &&
			(curUPF.NodeID.NodeIdType == pfcpType.NodeIdTypeFqdn || nodeID.NodeIdType == pfcpType.NodeIdTypeFqdn) {
			curUPFNodeIdIP := curUPF.NodeID.ResolveNodeIdToIp().To4()
			nodeIdIP := nodeID.ResolveNodeIdToIp().To4()
			logger.CtxLog.Tracef("RetrieveUPF - upfNodeIdIP:[%+v], nodeIdIP:[%+v]", curUPFNodeIdIP, nodeIdIP)
			if reflect.DeepEqual(curUPFNodeIdIP, nodeIdIP) {
				targetUPF = curUPF
				return false
			}
		} else if reflect.DeepEqual(curUPF.NodeID, nodeID) {
			targetUPF = curUPF
			return false
		}
		return true
	})

	return targetUPF
}

// *** add unit test ***//
func RemoveUPFNodeByNodeID(nodeID pfcpType.NodeID) bool {
	upfID := ""
	upfPool.Range(func(key, value interface{}) bool {
		upfID = key.(string)
		upf := value.(*UPF)
		if upf.NodeID.NodeIdType != nodeID.NodeIdType &&
			(upf.NodeID.NodeIdType == pfcpType.NodeIdTypeFqdn || nodeID.NodeIdType == pfcpType.NodeIdTypeFqdn) {
			upfNodeIdIP := upf.NodeID.ResolveNodeIdToIp().To4()
			nodeIdIP := nodeID.ResolveNodeIdToIp().To4()
			logger.CtxLog.Tracef("RemoveUPF - upfNodeIdIP:[%+v], nodeIdIP:[%+v]", upfNodeIdIP, nodeIdIP)
			if reflect.DeepEqual(upfNodeIdIP, nodeIdIP) {
				return false
			}
		} else if reflect.DeepEqual(upf.NodeID, nodeID) {
			return false
		}
		upfID = ""
		return true
	})

	if upfID != "" {
		upfPool.Delete(upfID)
		return true
	}
	return false
}

func SelectUPFByDnn(dnn string) *UPF {
	var upf *UPF
	upfPool.Range(func(key, value interface{}) bool {
		upf = value.(*UPF)
		if upf.UPIPInfo.Assoni && upf.UPIPInfo.NetworkInstance.NetworkInstance == dnn {
			return false
		}
		upf = nil
		return true
	})
	return upf
}

func (upf *UPF) pdrID() (uint16, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return 0, err
	}

	var pdrID uint16
	if tmpID, err := upf.pdrIDGenerator.Allocate(); err != nil {
		return 0, err
	} else {
		pdrID = uint16(tmpID)
	}

	return pdrID, nil
}

func (upf *UPF) farID() (uint32, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return 0, err
	}

	var farID uint32
	if tmpID, err := upf.farIDGenerator.Allocate(); err != nil {
		return 0, err
	} else {
		farID = uint32(tmpID)
	}

	return farID, nil
}

func (upf *UPF) barID() (uint8, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return 0, err
	}

	var barID uint8
	if tmpID, err := upf.barIDGenerator.Allocate(); err != nil {
		return 0, err
	} else {
		barID = uint8(tmpID)
	}

	return barID, nil
}

func (upf *UPF) qerID() (uint32, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return 0, err
	}

	var qerID uint32
	if tmpID, err := upf.qerIDGenerator.Allocate(); err != nil {
		return 0, err
	} else {
		qerID = uint32(tmpID)
	}

	return qerID, nil
}

func (upf *UPF) urrID() (uint32, error) {
	var urrID uint32
	if tmpID, err := upf.urrIDGenerator.Allocate(); err != nil {
		return 0, err
	} else {
		urrID = uint32(tmpID)
	}

	return urrID, nil
}

func (upf *UPF) AddPDR() (*PDR, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return nil, err
	}

	pdr := new(PDR)
	if PDRID, err := upf.pdrID(); err != nil {
		return nil, err
	} else {
		pdr.PDRID = PDRID
		upf.pdrPool.Store(pdr.PDRID, pdr)
	}

	if newFAR, err := upf.AddFAR(); err != nil {
		return nil, err
	} else {
		pdr.FAR = newFAR
	}

	return pdr, nil
}

func (upf *UPF) AddFAR() (*FAR, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return nil, err
	}

	far := new(FAR)
	if FARID, err := upf.farID(); err != nil {
		return nil, err
	} else {
		far.FARID = FARID
		upf.farPool.Store(far.FARID, far)
	}

	return far, nil
}

func (upf *UPF) AddBAR() (*BAR, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return nil, err
	}

	bar := new(BAR)
	if BARID, err := upf.barID(); err != nil {
	} else {
		bar.BARID = BARID
		upf.barPool.Store(bar.BARID, bar)
	}

	return bar, nil
}

func (upf *UPF) AddQER() (*QER, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return nil, err
	}

	qer := new(QER)
	if QERID, err := upf.qerID(); err != nil {
	} else {
		qer.QERID = QERID
		upf.qerPool.Store(qer.QERID, qer)
	}

	return qer, nil
}

func (upf *UPF) AddURR(urrId uint32, opts ...UrrOpt) (*URR, error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err := fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return nil, err
	}

	urr := new(URR)
	urr.MeasureMethod = MesureMethodVol
	urr.MeasurementInformation = MeasureInformation(true, false)

	for _, opt := range opts {
		opt(urr)
	}

	if urrId == 0 {
		if URRID, err := upf.urrID(); err != nil {
		} else {
			urr.URRID = URRID
			upf.urrPool.Store(urr.URRID, urr)
		}
	} else {
		urr.URRID = urrId
		upf.urrPool.Store(urr.URRID, urr)
	}
	return urr, nil
}

func (upf *UPF) GetQERById(qerId uint32) *QER {
	qer, ok := upf.qerPool.Load(qerId)
	if ok {
		return qer.(*QER)
	}
	return nil
}

// *** add unit test ***//
func (upf *UPF) RemovePDR(pdr *PDR) (err error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err = fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return err
	}

	upf.pdrIDGenerator.FreeID(int64(pdr.PDRID))
	upf.pdrPool.Delete(pdr.PDRID)
	return nil
}

// *** add unit test ***//
func (upf *UPF) RemoveFAR(far *FAR) (err error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err = fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return err
	}

	upf.farIDGenerator.FreeID(int64(far.FARID))
	upf.farPool.Delete(far.FARID)
	return nil
}

// *** add unit test ***//
func (upf *UPF) RemoveBAR(bar *BAR) (err error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err = fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return err
	}

	upf.barIDGenerator.FreeID(int64(bar.BARID))
	upf.barPool.Delete(bar.BARID)
	return nil
}

// *** add unit test ***//
func (upf *UPF) RemoveQER(qer *QER) (err error) {
	if upf.UPFStatus != AssociatedSetUpSuccess {
		err = fmt.Errorf("UPF[%s] not Associate with SMF", upf.GetNodeIDString())
		return err
	}

	upf.qerIDGenerator.FreeID(int64(qer.QERID))
	upf.qerPool.Delete(qer.QERID)
	return nil
}

func (upf *UPF) isSupportSnssai(snssai *SNssai) bool {
	for _, snssaiInfo := range upf.SNssaiInfos {
		if snssaiInfo.SNssai.Equal(snssai) {
			return true
		}
	}
	return false
}

func (upf *UPF) ProcEachSMContext(procFunc func(*SMContext)) {
	smContextPool.Range(func(key, value interface{}) bool {
		smContext := value.(*SMContext)
		if smContext.SelectedUPF != nil && smContext.SelectedUPF == upf {
			procFunc(smContext)
		}
		return true
	})
}

func (upf *UPF) MatchedSelection(selection *UPFSelectionParams) bool {
	for _, snssaiInfo := range upf.SNssaiInfos {
		currentSnssai := snssaiInfo.SNssai
		if currentSnssai.Equal(selection.SNssai) {
			for _, dnnInfo := range snssaiInfo.DnnList {
				if dnnInfo.Dnn == selection.Dnn {
					if selection.Dnai == "" {
						return true
					} else if dnnInfo.ContainsDNAI(selection.Dnai) {
						return true
					}
				}
			}
		}
	}
	return false
}
