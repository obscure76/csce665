package net.floodlightcontroller.bwaas;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IBWaaService extends IFloodlightService {
	public void provideBW(int src, int dst);
	public void resetBW(int src, int dst);
}
