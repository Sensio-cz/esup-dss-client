package org.esupportail.esupdssclient.api;

import java.text.MessageFormat;
import java.util.ResourceBundle;

public class OpenSC implements Product {

    private String version;
    private boolean enabled = true;

    public OpenSC() {
        super();
    }

    public OpenSC(String version, boolean enabled) {
        this.version = version;
        this.enabled = enabled;
    }

    public String getLabel() {
        ResourceBundle bundle = ResourceBundle.getBundle("bundles/api");
        if (enabled) {
            return MessageFormat.format(bundle.getString("product.selection.opensc"), version != null ? version : "OpenSC");
        } else {
            return bundle.getString("product.selection.opensc.not.detected");
        }
    }

    public String getVersion() {
        return version;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
