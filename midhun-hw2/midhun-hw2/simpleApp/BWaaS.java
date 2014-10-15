package net.floodlightcontroller.bwaas;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.learningswitch.ILearningSwitchService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LDUpdate;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.storage.IStorageSourceService;
import net.floodlightcontroller.topology.ITopologyListener;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.util.OFMessageDamper;

public class BWaaS implements IFloodlightModule, IOFMessageListener, IBWaaService {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	protected ITopologyService topology;
	protected myTopoListener topoListener = new myTopoListener();
	protected IRoutingService routingEngine;
	protected IDeviceService deviceService;
	protected Map<NodePortTuple, LinkedList<FlowInfo>> nodePortFlowMap;
	protected Map<Integer, MACAddress> IPMACMap;
	protected Map<Integer, HostInfo> portHostMap = new HashMap<Integer, HostInfo>();
	protected ILearningSwitchService LSwitchService;
	public static final int FORWARDING_APP_ID = 2;
    protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
    protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	protected OFMessageDamper messageDamper;
	protected IRestApiService restApi;
	protected static int bwSrc;
	protected static int bwDst;
	protected static List<NodePortTuple> bwPath = new LinkedList<NodePortTuple>();
	protected static Map<NodePortTuple, NodePortTuple > bwPathMap;
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
						logger.debug("{} {}",sw,swport );
						break;
					case SWITCH_REMOVED:
						break;
					default:
						break;
				}
			}
		}
		
	}
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub //167772162
		return "BWaaS";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	public void dropFlow(IOFSwitch sw,FloodlightContext cntx, OFPacketIn pi)
	{
		OFMatch match = new OFMatch();
		IRoutingDecision decision = null;
		logger.info("Dropping flow on {} {}",sw, pi.toString());
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        if (cntx != null)
            decision =
                    IRoutingDecision.rtStore.get(cntx,
                                                 IRoutingDecision.CONTEXT_DECISION);
        if (decision!=null && decision.getWildcards() != null) {
            match.setWildcards(decision.getWildcards());
        }

        // Create flow-mod based on packet-in and src-switch
        OFFlowMod fm =
                (OFFlowMod) floodlightProvider.getOFMessageFactory()
                                              .getMessage(OFType.FLOW_MOD);
        List<OFAction> actions = new ArrayList<OFAction>(); // Set no action to
                                                            // drop
        long cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);

        fm.setCookie(cookie)
          .setHardTimeout((short) 0)
          .setIdleTimeout((short) 5)
          .setBufferId(OFPacketOut.BUFFER_ID_NONE)
          .setMatch(match)
          .setActions(actions)
          .setLengthU(OFFlowMod.MINIMUM_LENGTH); // +OFActionOutput.MINIMUM_LENGTH);

        try {
            logger.info("write drop flow-mod sw={} match={} flow-mod={}",
                    new Object[] { sw, match, fm });
            messageDamper.write(sw, fm, cntx);
        } catch (IOException e) {
            logger.error("Failure writing drop flow mod", e);
        }
	}
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		Ethernet eth =
				IFloodlightProviderService.bcStore.get(cntx,
						IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IPacket pkt = eth.getPayload();
		OFPacketIn OFpkt = (OFPacketIn) msg;
		
		switch(msg.getType())
		{
			case FLOW_REMOVED:
				//Remove the flow removed
				logger.info("Flow removed {}", msg);
				break;
			default:
				break;
		}
		if(pkt instanceof ARP)
		{
			//ARP flow; Dont store
			ARP p4 = (ARP) pkt;
			int srcIP = IPv4.toIPv4Address(p4.getSenderProtocolAddress());
			int dstIP = IPv4.toIPv4Address(p4.getTargetProtocolAddress());
			if(portHostMap.containsKey(srcIP))
			{					
				
			} else {
				IPMACMap.put(srcIP, eth.getSourceMAC());
				portHostMap.put(srcIP, new HostInfo(eth.getSourceMAC(), srcIP, OFpkt.getInPort(), sw, eth.getVlanID() ));
			}
			if(portHostMap.containsKey(dstIP))
			{
				HostInfo hdst = portHostMap.get(dstIP);
				Route route =
						routingEngine.getRoute(sw.getId(),
								OFpkt.getInPort(), 
								hdst.swId.getId(),
								hdst.swPort, 0); 
				if(route != null)
				{
					//Check for existing flows along the path
					if(bwPath.isEmpty()&&(bwSrc-srcIP ==0 && bwDst-dstIP ==0))
					{
						bwPath=route.getPath();
						for(NodePortTuple npt : bwPath)
						{
							logger.info("BW path updated");
							bwPathMap.put(npt, npt);
						}
					}
				} else {
					logger.info("Route is null");
				}
			}
		} else if (pkt instanceof IPv4) {
				logger.debug("Current cntx {}", cntx);
				IPv4 p4 = (IPv4) pkt;
				Integer dstIP = p4.getDestinationAddress();
				Integer srcIP = p4.getSourceAddress();
				
				if(!portHostMap.containsKey(p4.getSourceAddress())) {
					portHostMap.put(p4.getSourceAddress(), new HostInfo(eth.getSourceMAC(), p4.getSourceAddress(), OFpkt.getInPort(), sw, eth.getVlanID() ));
				}
							
				//Store the flow
				if(portHostMap.containsKey(dstIP))
				{
					HostInfo h = portHostMap.get(dstIP);
					Route route =
                    routingEngine.getRoute(sw.getId(),
                    					   OFpkt.getInPort(),
                                            h.swId.getId(),
                                            h.swPort, 0); 
					logger.info("Pkt received: route {}", route);
					if(route == null)
						return Command.CONTINUE;
					if(route != null)
					{
						//Check for existing flows along the path
						if(bwPath.isEmpty()&&(bwSrc-srcIP ==0 && bwDst-dstIP ==0))
						{
							bwPath=route.getPath();
							logger.info("BW path updated");
							for(NodePortTuple npt : bwPath)
							{
								bwPathMap.put(npt, npt);
							}
							logger.info("{}", bwPathMap);
						}
					} 
					List<NodePortTuple> lnpp = route.getPath();
					
					for(NodePortTuple npt : lnpp)
					{
							if(bwPathMap.containsKey(npt))
							{
								if((srcIP - bwSrc ==0 && dstIP - bwDst ==0) || (dstIP - bwSrc ==0 && srcIP - bwDst ==0))
								{
									//Required flow
									logger.debug("flow {}{}", srcIP, dstIP);
								} else {
									try {
										dropFlow(sw, cntx, OFpkt);
									} catch (Exception ex) {
										logger.error("Exception {}", ex);
									}
									
								}
							}
					}
				}
		}
		
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IBWaaService.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IBWaaService.class, this);
	    return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IStorageSourceService.class);
        l.add(IRestApiService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(BWaaS.class);
		IPMACMap = new ConcurrentHashMap<Integer, MACAddress>();
		bwPathMap = new ConcurrentHashMap<NodePortTuple, NodePortTuple >(); 
		portHostMap = new ConcurrentHashMap<Integer, HostInfo>();
		nodePortFlowMap = new ConcurrentHashMap<NodePortTuple, LinkedList<FlowInfo>>();
		restApi = context.getServiceImpl(IRestApiService.class);
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
                 EnumSet.of(OFType.FLOW_MOD),
                 OFMESSAGE_DAMPER_TIMEOUT);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new BWaaSWebRoutable());
		this.topology = context.getServiceImpl(ITopologyService.class);
		this.routingEngine = context.getServiceImpl(IRoutingService.class);
		this.LSwitchService = context.getServiceImpl(ILearningSwitchService.class);
		this.deviceService = context.getServiceImpl(IDeviceService.class);
		this.topology.addListener(topoListener);
	}
	
	protected class FlowInfo {
		public Integer srcIP;
		public Integer dstIP;
		public short srcPort;
		public IOFSwitch srcSw;
		OFPacketIn OFpkt;
		FloodlightContext cntx;
		
		public FlowInfo(Integer sIP, Integer dIP,  short sport, IOFSwitch sSw, FloodlightContext cx, OFPacketIn pkt)
		{
			srcIP = sIP;
			dstIP = dIP;
			srcPort = sport;
			srcSw = sSw;
			cntx = cx;
			OFpkt = pkt;
		}
		@Override
	    public String toString() {
	        return "\n srcIP =" + srcIP + ", dstIP="
	                + dstIP  + ", srcPort=" + srcPort
	                + "cntx =" + cntx
	                ;
	    }
	    public boolean equals(Object obj) {
	        if (this == obj)
	            return true;
	        if (!super.equals(obj))
	            return false;
	        if (!(obj instanceof FlowInfo))
	            return false;
	        FlowInfo other = (FlowInfo) obj;
	        if (srcIP != other.srcIP)
	            return false;
	        if (dstIP != other.dstIP)
	            return false;
	        return true;
	    }
	    
	}
	public class  HostInfo
	{
		public MACAddress MAC;
		public Integer IPv4address;
		public short swPort;
		public IOFSwitch swId;
		public Short vlanId;

		public HostInfo(){}
		public HostInfo(MACAddress macaddr, Integer ipaddr, Short port, IOFSwitch sw, Short vlan)
		{
			MAC = macaddr;
			IPv4address = ipaddr;
			swPort = port;
			swId = sw;
			vlanId = vlan;
		}
		@Override
	    public String toString() {
	        return "{ MAC = " + MAC.toString()  + " IP = " + IPv4address.toString() + " sw = " + swId.toString()+ " swport = " + swPort  + "}";
	    }
	}

	@Override
	public void provideBW(int src, int dst) {
		/* Provide Bandwidth along the path from src to dst by dropping the other traffic*/		
		bwSrc = src;
		bwDst = dst;
		if(!portHostMap.containsKey(src) || !portHostMap.containsKey(dst))
			return;
		HostInfo hsrc = portHostMap.get(src);
		HostInfo hdst = portHostMap.get(dst);
		logger.info("Providing BW from {} to {}", src, dst);
		logger.info("bwSrc {} {}", bwSrc, bwDst);
		Route route =
                routingEngine.getRoute(hsrc.swId.getId(),
                						hsrc.swPort, 
                                        hdst.swId.getId(),
                                        hdst.swPort, 0); 
		if(route != null)
		{
			//Check for existing flows along the path
			bwPath=route.getPath();
			for(NodePortTuple npt : bwPath)
			{
				logger.info("BW path updated");
				bwPathMap.put(npt, npt);
			}
		} else {
			logger.info("Route is null");
		}
	}

	@Override
	public void resetBW(int src, int dst) {
		// TODO Auto-generated method stub
		bwSrc = 0;
		bwDst = 0;
		bwPath.clear();
		bwPathMap.clear();
	}

}
