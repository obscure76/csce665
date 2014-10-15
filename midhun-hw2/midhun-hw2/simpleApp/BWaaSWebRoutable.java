package net.floodlightcontroller.bwaas;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;
import net.floodlightcontroller.restserver.RestletRoutable;

public class BWaaSWebRoutable implements RestletRoutable {

	@Override
	public Restlet getRestlet(Context context) {
		Router router = new Router(context);
        router.attach("/{src}/{dst}/{enable}", BWaaServiceResource.class);
        return router;
	}
    public String basePath() {
        return "/wm/bwaas";
    }
}
