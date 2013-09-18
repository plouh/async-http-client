package org.asynchttpclient.providers.netty4.pool;

import io.netty.channel.Channel;

import org.asynchttpclient.ConnectionsPool;

public class NonConnectionsPool implements ConnectionsPool<String, Channel> {

    public boolean offer(String uri, Channel connection) {
        return false;
    }

    public Channel poll(String uri) {
        return null;
    }

    public boolean removeAll(Channel connection) {
        return false;
    }

    public boolean canCacheConnection() {
        return true;
    }

    public void destroy() {
    }
}