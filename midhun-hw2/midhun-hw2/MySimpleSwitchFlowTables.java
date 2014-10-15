package net.floodlightcontroller.mactracker;

import java.io.IOException;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.HashMap;
import java.util.Set;

import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LDUpdate;
import net.floodlightcontroller.mactracker.MACTracker.HostInfo;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.ITopologyListener;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.OFMessageDamper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MACTracker implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected  HashMap<Integer, HostInfo> portHostMap = new HashMap<Integer, HostInfo>();
	public static final short TYPE_ARP = 0x0806;
	protected IRoutingService routingEngine;
	protected ITopologyService topology;
	protected myTopoListener topoListener = new myTopoListener();
	protected IDeviceService devService;
	protected OFMessageDamper messageDamper;
	protected devListener myDevListener = new devListener();
	
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms

	public static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
	public static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite

	public static final short FLOWMOD_DEFAULT_IDLE_TIMEOUT_CONSTANT = 5;
	public static final short FLOWMOD_DEFAULT_HARD_TIMEOUT_CONSTANT = 0;
	public static final int FORWARDING_APP_ID = 2;

	public class myTopoListener implements ITopologyListener
	{

		@Override
		public void topologyChanged(List<LDUpdate> linkUpdates) {
			// TODO Auto-generated method stub
			logger.info("Topology changes {}", linkUpdates);
			long sw;
			short swport;
			for(LDUpdate l: linkUpdates)
			{
				switch(l.getOperation())
				{
					case LINK_REMOVED:
						sw = l.getSrc();
						swport = l.getSrcPort();
						logger.debug("{}",swport );
						break;
					case SWITCH_REMOVED:
						sw = l.getSrc();
						LinkedList<Integer> remList = new LinkedList<Integer>();
						swport = l.getSrcPort();
						Iterator<Entry<Integer, HostInfo>> it = portHostMap.entrySet().iterator();
						while(it.hasNext())
						{
							Map.Entry<Integer, HostInfo> pair = it.next();
							HostInfo h = pair.getValue();
							if(h.swId == sw)
							{
								remList.add(pair.getKey());
							}
						}
						for(Integer i : remList)
						{
							portHostMap.remove(i);
						}
						break;
					default:
						break;
				}
			}
		}
		
	}
	public class devListener implements IDeviceListener
	{

		@Override
		public String getName() {
			// TODO Auto-generated method stub
			return null;
		}
		

		@Override
		public boolean isCallbackOrderingPrereq(String type, String name) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isCallbackOrderingPostreq(String type, String name) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void deviceAdded(IDevice device) {
			// TODO Auto-generated method stub
			logger.info("Devide added {}", device);
		}

		@Override
		public void deviceRemoved(IDevice device) {
			// TODO Auto-generated method stub
			logger.info("Devide removed {}", device);
		}

		@Override
		public void deviceMoved(IDevice device) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void deviceIPV4AddrChanged(IDevice device) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void deviceVlanChanged(IDevice device) {
			// TODO Auto-generated method stub
			
		}
		
	}
	
	public Comparator<SwitchPort> clusterIdComparator =
			new Comparator<SwitchPort>() {
		@Override
		public int compare(SwitchPort d1, SwitchPort d2) {
			Long d1ClusterId =
					topology.getL2DomainId(d1.getSwitchDPID());
			Long d2ClusterId =
					topology.getL2DomainId(d2.getSwitchDPID());
			return d1ClusterId.compareTo(d2ClusterId);
		}
	};

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return MACTracker.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	protected OFMatch wildcard(OFMatch match, IOFSwitch sw,
			Integer wildcard_hints) {
		if (wildcard_hints != null) {
			return match.clone().setWildcards(wildcard_hints.intValue());
		}
		return match.clone();
	}

	protected void pushPacket(IOFSwitch sw, OFPacketIn pi,
			boolean useBufferId,
			short outport, FloodlightContext cntx) {

		if (pi == null) {
			return;
		}

		// The assumption here is (sw) is the switch that generated the
		// packet-in. If the input port is the same as output port, then
		// the packet-out should be ignored.
		if (pi.getInPort() == outport) {
			if (logger.isDebugEnabled()) {
				logger.debug("Attempting to do packet-out to the same " +
						"interface as packet-in. Dropping packet. " +
						" SrcSwitch={}, pi={}",
						new Object[]{sw, pi});
				return;
			}
		}

		if (logger.isTraceEnabled()) {
			logger.trace("PacketOut srcSwitch={} pi={}",
					new Object[] {sw, pi});
		}

		OFPacketOut po =
				(OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(new OFActionOutput(outport, (short) 0xffff));

		po.setActions(actions)
		.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		short poLength =
				(short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);

		if (useBufferId) {
			po.setBufferId(pi.getBufferId());
		} else {
			po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		}

		if (po.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = pi.getPacketData();
			poLength += packetData.length;
			po.setPacketData(packetData);
		}

		po.setInPort(pi.getInPort());
		po.setLength(poLength);

		try {
			//counterStore.updatePktOutFMCounterStoreLocal(sw, po);
			logger.info("writing rule {} to switch {}",po, sw);
			messageDamper.write(sw, po, cntx);
		} catch (IOException e) {
			logger.error("Failure writing packet out", e);
		}
	}

	public boolean pushRoute(Route route, OFMatch match,
			Integer wildcard_hints,
			OFPacketIn pi,
			long pinSwitch,
			long cookie,
			FloodlightContext cntx,
			boolean reqeustFlowRemovedNotifn,
			boolean doFlush,
			short   flowModCommand) {

		boolean srcSwitchIncluded = false;
		OFFlowMod fm =
				(OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD);
		OFActionOutput action = new OFActionOutput();
		action.setMaxLength((short)0xffff);
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(action);

		fm.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setBufferId(OFPacketOut.BUFFER_ID_NONE)
		.setCookie(cookie)
		.setCommand(flowModCommand)
		.setMatch(match)
		.setActions(actions)
		.setLengthU(OFFlowMod.MINIMUM_LENGTH+OFActionOutput.MINIMUM_LENGTH);

		List<NodePortTuple> switchPortList = route.getPath();
		logger.info("Path = {}", route.getPath());
		for (int indx = switchPortList.size()-1; indx > 0; indx -= 2) {
			// indx and indx-1 will always have the same switch DPID.
			long switchDPID = switchPortList.get(indx).getNodeId();
			IOFSwitch sw = floodlightProvider.getSwitch(switchDPID);
			if (sw == null) {
				if (logger.isWarnEnabled()) {
					logger.warn("Unable to push route, switch at DPID {} " +
							"not available", switchDPID);
				}
				return srcSwitchIncluded;
			}

			// set the match.
			fm.setMatch(wildcard(match, sw, wildcard_hints));

			// set buffer id if it is the source switch
			if (1 == indx) {
				// Set the flag to request flow-mod removal notifications only for the
				// source switch. The removal message is used to maintain the flow
				// cache. Don't set the flag for ARP messages - TODO generalize check
				if ((reqeustFlowRemovedNotifn)
						&& (match.getDataLayerType() != Ethernet.TYPE_ARP)) {
					/**with new flow cache design, we don't need the flow removal message from switch anymore
   fm.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);
					 */
					match.setWildcards(fm.getMatch().getWildcards());
				}
			}

			short outPort = switchPortList.get(indx).getPortId();
			short inPort = switchPortList.get(indx-1).getPortId();
			// set input and output ports on the switch
			fm.getMatch().setInputPort(inPort);
			((OFActionOutput)fm.getActions().get(0)).setPort(outPort);

			try {
				//counterStore.updatePktOutFMCounterStoreLocal(sw, fm);
				
					logger.info("Pushing Route flowmod routeIndx={} " +
							"sw={} inPort={} outPort={}",
							new Object[] {indx,
							sw,
							fm.getMatch().getInputPort(),
							outPort });
				
				messageDamper.write(sw, fm, cntx);
				if (doFlush) {
					sw.flush();
					//counterStore.updateFlush();
				}

				// Push the packet out the source switch
				if (sw.getId() == pinSwitch) {
					pushPacket(sw, pi, false, outPort, cntx);
					srcSwitchIncluded = true;
				}
			} catch (IOException e) {
				logger.error("Failure writing flow mod", e);
			}
			try {
				fm = fm.clone();
			} catch (CloneNotSupportedException e) {
				logger.error("Failure cloning flow mod", e);
			}
		}
		return srcSwitchIncluded;
	}

	private void forwardPkt(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Integer dstip)
	{
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());

		//IRoutingDecision decisionn = null;
		//Check if we had a routing decision already made for this
		/*if (cntx != null)
            decisionn =
                    IRoutingDecision.rtStore.get(cntx,
                                                 IRoutingDecision.CONTEXT_DECISION);
		if(decisionn != null)
		{
			 switch(decisionn.getRoutingAction()) {
             case NONE:
                 // don't do anything
                 return;
             case FORWARD_OR_FLOOD:
             case FORWARD:
            	 break;
             case MULTICAST:
                 // treat as broadcast
                 floodPkt(sw, pi, cntx);
                 return;
             case DROP:
                 return;
             default:
                 logger.error("Unexpected decision made for this packet-in={}",
                         pi, decisionn.getRoutingAction());
                 return;
         }
		}*/
		// Check if we have the location of the destination
		
		if(portHostMap.containsKey(dstip))
		{
			logger.info("In forwarding module");
			HostInfo dst = portHostMap.get(dstip);

			Route route =
					routingEngine.getRoute(sw.getId(),
							pi.getInPort(),
							dst.swId,
							dst.swPort, 0); //cookie = 0, i.e., default route
			long id = sw.getId();
			short port = pi.getInPort();
			logger.info("src {} {}", id, port);
			logger.info(" dst {} {}", dst.swId, dst.swPort);
			if (route != null) {
				
				logger.info("pushRoute match={} route={} " +
							"destination={}:{}",
							new Object[] {match, route,
							dst.swId,
							dst.swPort});
				
				long cookie =
				      AppCookie.makeCookie(FORWARDING_APP_ID, 0);

				// if there is prior routing decision use wildcard
				Integer wildcard_hints = null;
				IRoutingDecision decision = null;
				if (cntx != null) {
					decision = IRoutingDecision.rtStore.get(cntx,
							IRoutingDecision.CONTEXT_DECISION);
				}
				if (decision != null) {
					wildcard_hints = decision.getWildcards();
				} else {
					// L2 only wildcard if there is no prior route decision
					wildcard_hints = ((Integer) sw
							.getAttribute(IOFSwitch.PROP_FASTWILDCARDS))
							.intValue()
							& ~OFMatch.OFPFW_IN_PORT
							& ~OFMatch.OFPFW_DL_VLAN
							& ~OFMatch.OFPFW_DL_SRC
							& ~OFMatch.OFPFW_DL_DST
							& ~OFMatch.OFPFW_NW_SRC_MASK
							& ~OFMatch.OFPFW_NW_DST_MASK;
				}
				pushRoute(route, match, wildcard_hints, pi, sw.getId(), cookie,
                          cntx, false, false,
                          OFFlowMod.OFPFC_ADD);
			} else {
				logger.info("No route!!");
			}
		} else {
			logger.info("Dst Not known!! Flood");
			floodPkt(sw, pi, cntx);
		}

	}

	private void floodPkt(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx)
	{
		if (topology.isIncomingBroadcastAllowed(sw.getId(),
				pi.getInPort()) == false) {

			return;
		}

		// Set Action to flood
		OFPacketOut po =
				(OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
		List<OFAction> actions = new ArrayList<OFAction>();
		if (sw.hasAttribute(IOFSwitch.PROP_SUPPORTS_OFPP_FLOOD)) {
			actions.add(new OFActionOutput(OFPort.OFPP_FLOOD.getValue(),
					(short)0xFFFF));
		} else {
			actions.add(new OFActionOutput(OFPort.OFPP_ALL.getValue(),
					(short)0xFFFF));
		}
		po.setActions(actions);
		po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

		// set buffer-id, in-port and packet-data based on packet-in
		short poLength = (short)(po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);
		po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		po.setInPort(pi.getInPort());
		byte[] packetData = pi.getPacketData();
		poLength += packetData.length;
		po.setPacketData(packetData);
		po.setLength(poLength);

		try {
			messageDamper.write(sw, po, cntx);
		} catch (IOException e) {
			logger.error("Error {}", this.getName());;
		}

		return;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
        l.add(IDeviceService.class);
        l.add(IRoutingService.class);
        l.add(ITopologyService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		macAddresses = new ConcurrentSkipListSet<Long>();
		logger = LoggerFactory.getLogger(MACTracker.class);
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		this.routingEngine = context.getServiceImpl(IRoutingService.class);
		this.topology = context.getServiceImpl(ITopologyService.class);
		this.devService = context.getServiceImpl(IDeviceService.class);
		devService.addListener(myDevListener);
		this.topology.addListener(topoListener);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub

		Ethernet eth =
				IFloodlightProviderService.bcStore.get(cntx,
						IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Long sourceMACHash = Ethernet.toLong(eth.getSourceMACAddress());
		logger.debug("Eth = {}",eth);
		//IDeviceListener devListener;
		
		OFPacketIn pktIn = (OFPacketIn) msg;
		IPacket pkt = eth.getPayload();

		long id = sw.getId();
		int srcIP=0;
		int dstIP = 0; 
		short vlan = eth.getVlanID();
		if(pkt instanceof ARP)
		{
			ARP p4 = (ARP) pkt;
			srcIP = IPv4.toIPv4Address(p4.getSenderProtocolAddress());
			dstIP = IPv4.toIPv4Address(p4.getTargetProtocolAddress());
			if(!portHostMap.containsKey(srcIP)) {
				logger.info("Learned {} {} on ", srcIP, pktIn.getInPort()+sw.toString());
				HostInfo h = new HostInfo(sourceMACHash, srcIP, pktIn.getInPort(),id, vlan);
				portHostMap.put(srcIP, h);
			}
			for(Long l : topology.getSwitchesInOpenflowDomain(sw.getId()))
			{
				IOFSwitch swflood = floodlightProvider.getSwitch(l);
				floodPkt(swflood, pktIn, cntx);
			}
			return Command.CONTINUE;
		} else {
			try
			{
				IPv4 p4 = (IPv4) pkt;
				srcIP = p4.getSourceAddress();
				if(!portHostMap.containsKey(srcIP)) {
					logger.info("Learned {} {} on ", srcIP, pktIn.getInPort());
					logger.info(sw.toString());
					HostInfo h = new HostInfo(sourceMACHash, srcIP, pktIn.getInPort(),id, vlan);
					portHostMap.put(srcIP, h);
				}
				if(portHostMap.containsKey(dstIP))
				{
				
					forwardPkt(sw, pktIn, cntx, dstIP);
				} else{
					floodPkt(sw, pktIn, cntx);
				}
			} catch(Exception ex) {
				logger.debug("Exception :O \n");
			}

		}
		return Command.CONTINUE;
	}
	
	public class  HostInfo
	{
		public Long MAC;
		public Integer IPv4address;
		public short swPort;
		public long swId;
		public Short vlanId;

		public HostInfo(){}
		public HostInfo(Long macaddr, Integer ipaddr, Short port, Long sw, Short vlan)
		{
			MAC = macaddr;
			IPv4address = ipaddr;
			swPort = port;
			swId = sw;
			vlanId = vlan;
		}

	}

}


