package net.floodlightcontroller.bwaas;


import net.floodlightcontroller.packet.IPv4;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;



public class BWaaServiceResource extends ServerResource{
	 @Get("json")
	    public Object handleRequest() {
		 IBWaaService bwaas =
	                (IBWaaService)getContext().getAttributes().
	                get(IBWaaService.class.getCanonicalName());

	        String src = (String) getRequestAttributes().get("src");
	        String dst = (String) getRequestAttributes().get("dst");
	        String enable = (String) getRequestAttributes().get("enable");
	        System.out.print("Received " + src + dst + enable);
	        if(enable.equals("reserve"))
	        {
	        	bwaas.provideBW(IPv4.toIPv4Address(src), IPv4.toIPv4Address(dst));
	        	return "Path from "+ src + " to "+ dst + " Will be reserved\n";
	        } else if(enable.equals("free")) {
	        	bwaas.resetBW(IPv4.toIPv4Address(src), IPv4.toIPv4Address(dst));
	        	return "Path from "+ src + " to "+ dst + " Will be freed\n";
	        } else {
	        	return "Unknown option\n";
	        }  
	    }

}
