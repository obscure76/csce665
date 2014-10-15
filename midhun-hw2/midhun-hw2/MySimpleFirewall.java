package net.floodlightcontroller.mactracker;

import java.io.IOException;
import java.util.Collection;
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

import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.HashMap;
import java.util.Set;

import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LDUpdate;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.topology.ITopologyListener;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.OFMessageDamper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MACTracker implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected  HashMap<Integer, HostInfo> portHostMap = new HashMap<Integer, HostInfo>();
	public static final short TYPE_ARP = 0x0806;
	protected ITopologyService topology;
	protected myTopoListener topoListener = new myTopoListener();
	protected OFMessageDamper messageDamper;
	
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
							if(h.swId.getId() == sw)
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

	private void forwardPkt(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Integer dstip)
	{	
		logger.debug("In forwarding module");
		//167772162
		HostInfo dst = portHostMap.get(dstip);
		OFPacketOut po =
				(OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(new OFActionOutput(dst.swPort, (short) 0xffff));

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
		logger.info("{}",po);
		try {
			logger.info("writing to dst {}: {}", dst.swId, dst.swPort);
			messageDamper.write(dst.swId, po, cntx);
		} catch (IOException e) {
			logger.error("Error {}", this.getName());;
		}
	}
	
	protected OFMatch wildcard(OFMatch match, IOFSwitch sw,
			Integer wildcard_hints) {
		if (wildcard_hints != null) {
			return match.clone().setWildcards(wildcard_hints.intValue());
		}
		return match.clone();
	}
	
	private void dropPkt(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Integer dstIP)
	{
		OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        OFFlowMod fm =
                (OFFlowMod) floodlightProvider.getOFMessageFactory()
                                              .getMessage(OFType.FLOW_MOD);
        List<OFAction> actions = new ArrayList<OFAction>();
        long cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);

        fm.setCookie(cookie)
          .setHardTimeout((short) 0)
          .setIdleTimeout((short) 5)
          .setBufferId(OFPacketOut.BUFFER_ID_NONE)
          .setMatch(match)
          .setActions(actions)
          .setLengthU(OFFlowMod.MINIMUM_LENGTH); // +OFActionOutput.MINIMUM_LENGTH);

        try {
            messageDamper.write(sw, fm, cntx);
        } catch (IOException e) {
            logger.error("Failure writing drop flow mod", e);
        }
	}

	private void floodPkt(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx)
	{
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
		this.topology = context.getServiceImpl(ITopologyService.class);
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
		
		
		OFPacketIn pktIn = (OFPacketIn) msg;
		IPacket pkt = eth.getPayload();

		int srcIP = 0;
		int dstIP = 0; 
		short vlan = eth.getVlanID();
		if(pkt instanceof ARP)
		{
			ARP p4 = (ARP) pkt;
			srcIP = IPv4.toIPv4Address(p4.getSenderProtocolAddress());
			dstIP = IPv4.toIPv4Address(p4.getTargetProtocolAddress());
			if(!portHostMap.containsKey(srcIP)) {
				logger.info("Learned {} {} on ", srcIP, pktIn.getInPort()+sw.toString());
				HostInfo h = new HostInfo(sourceMACHash, srcIP, pktIn.getInPort(),sw, vlan);
				portHostMap.put(srcIP, h);
			}
			
			if(!portHostMap.containsKey(dstIP))
			{
				logger.info("\nIts ARP BROADCAST to unknown destination \n\n");
				floodPkt(sw, pktIn, cntx);
			} else {
				logger.info("ARP from {} {}",srcIP, dstIP);
				forwardPkt(sw, pktIn, cntx, dstIP);
			}
		} else {
			try
			{
				IPv4 p4 = (IPv4) pkt;
				srcIP = p4.getSourceAddress();
				dstIP = p4.getDestinationAddress();
				if(!portHostMap.containsKey(srcIP)) {
					logger.info("Learned {} {} on ", srcIP, pktIn.getInPort());
					HostInfo h = new HostInfo(sourceMACHash, srcIP, pktIn.getInPort(),sw, vlan);
					portHostMap.put(srcIP, h);
				}
				if((167772162 == srcIP && 167772163 == dstIP) ||
						(167772163 == srcIP && 167772162 == dstIP))
				{
					dropPkt(sw, pktIn, cntx, dstIP);
					return Command.CONTINUE;
				}
				if(portHostMap.containsKey(dstIP))
				{
					/* Forward */
					logger.info("Known dest: Forward");
					forwardPkt(sw, pktIn, cntx, dstIP);
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
		public IOFSwitch swId;
		public Short vlanId;

		public HostInfo(){}
		public HostInfo(Long macaddr, Integer ipaddr, Short port, IOFSwitch sw, Short vlan)
		{
			MAC = macaddr;
			IPv4address = ipaddr;
			swPort = port;
			swId = sw;
			vlanId = vlan;
		}

	}

}


