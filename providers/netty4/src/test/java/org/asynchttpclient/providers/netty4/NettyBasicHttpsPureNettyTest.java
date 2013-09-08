package org.asynchttpclient.providers.netty4;

import static org.testng.Assert.assertEquals;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.stream.ChunkedFile;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.GenericFutureListener;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URL;
import java.nio.channels.ClosedChannelException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class NettyBasicHttpsPureNettyTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(NettyBasicHttpsPureNettyTest.class);
    private static final int TIMEOUT = 300;
    private static final File SIMPLE_TEXT_FILE;

    static {
        try {
            SIMPLE_TEXT_FILE = new File(NettyBasicHttpsPureNettyTest.class.getClassLoader().getResource("SimpleTextFile.txt").toURI());
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private int port;
    private JettyServer server;

    private static class JettyServer {

        private static class EchoHandler extends AbstractHandler {

            @Override
            public void handle(String pathInContext, Request r, HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException, IOException {

                httpResponse.setContentType("text/html; charset=utf-8");
                Enumeration<?> e = httpRequest.getHeaderNames();
                String param;
                while (e.hasMoreElements()) {
                    param = e.nextElement().toString();

                    if (param.startsWith("LockThread")) {
                        try {
                            Thread.sleep(40 * 1000);
                        } catch (InterruptedException ex) { // nothing to do here
                        }
                    }

                    httpResponse.addHeader("X-" + param, httpRequest.getHeader(param));
                }

                Enumeration<?> i = httpRequest.getParameterNames();

                StringBuilder requestBody = new StringBuilder();
                while (i.hasMoreElements()) {
                    param = i.nextElement().toString();
                    httpResponse.addHeader("X-" + param, httpRequest.getParameter(param));
                    requestBody.append(param);
                    requestBody.append("_");
                }

                String pathInfo = httpRequest.getPathInfo();
                if (pathInfo != null)
                    httpResponse.addHeader("X-pathInfo", pathInfo);

                String queryString = httpRequest.getQueryString();
                if (queryString != null)
                    httpResponse.addHeader("X-queryString", queryString);

                httpResponse.addHeader("X-KEEP-ALIVE", httpRequest.getRemoteAddr() + ":" + httpRequest.getRemotePort());

                Cookie[] cs = httpRequest.getCookies();
                if (cs != null) {
                    for (Cookie c : cs) {
                        httpResponse.addCookie(c);
                    }
                }

                if (requestBody.length() > 0) {
                    httpResponse.getOutputStream().write(requestBody.toString().getBytes());
                }

                int size = 10 * 1024;
                if (httpRequest.getContentLength() > 0) {
                    size = httpRequest.getContentLength();
                }
                byte[] bytes = new byte[size];
                int pos = 0;
                if (bytes.length > 0) {
                    int read = 0;
                    while (read != -1) {
                        read = httpRequest.getInputStream().read(bytes, pos, bytes.length - pos);
                        pos += read;
                    }

                    httpResponse.getOutputStream().write(bytes);
                }

                httpResponse.setStatus(200);
                httpResponse.getOutputStream().flush();
                httpResponse.getOutputStream().close();
            }
        }

        private Server server;

        public JettyServer(int port) throws Exception {
            server = new Server();
            ClassLoader cl = getClass().getClassLoader();

            URL keystoreUrl = cl.getResource("ssltest-keystore.jks");
            String keyStoreFile = new File(keystoreUrl.toURI()).getAbsolutePath();
            LOGGER.info("SSL keystore path: {}", keyStoreFile);
            SslContextFactory sslContextFactory = new SslContextFactory(keyStoreFile);
            sslContextFactory.setKeyStorePassword("changeit");

            String trustStoreFile = new File(cl.getResource("ssltest-cacerts.jks").toURI()).getAbsolutePath();
            LOGGER.info("SSL certs path: {}", trustStoreFile);
            sslContextFactory.setTrustStore(trustStoreFile);
            sslContextFactory.setTrustStorePassword("changeit");

            SslSocketConnector connector = new SslSocketConnector(sslContextFactory);
            connector.setHost("127.0.0.1");
            connector.setPort(port);
            server.addConnector(connector);

            server.setHandler(new EchoHandler());
            server.start();
            LOGGER.info("Local HTTP server started successfully");
        }

        public void stop() throws Exception {
            server.stop();
        }
    }

    @BeforeClass(alwaysRun = true)
    public void setUpGlobal() throws Exception {
        port = Utils.findFreePort();
        server = new JettyServer(port);
    }

    @AfterClass(alwaysRun = true)
    public void tearDownGlobal() throws Exception {
        if (server != null)
            server.stop();
    }

    private static class MyChannelInitializer extends ChannelInitializer<Channel> {

        private SSLContext createSSLContext() {
            InputStream keyStoreStream = NettyBasicHttpsPureNettyTest.class.getResourceAsStream("ssltest-cacerts.jks");
            try {
                char[] keyStorePassword = "changeit".toCharArray();
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(keyStoreStream, keyStorePassword);

                // Set up key manager factory to use our key store
                char[] certificatePassword = "changeit".toCharArray();
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, certificatePassword);

                // Initialize the SSLContext to work with our key managers.
                KeyManager[] keyManagers = kmf.getKeyManagers();
                TrustManager[] trustManagers = new TrustManager[] { dummyTrustManager() };
                SecureRandom secureRandom = new SecureRandom();

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(keyManagers, trustManagers, secureRandom);

                return sslContext;
            } catch (Exception e) {
                throw new Error("Failed to initialize the server-side SSLContext", e);
            } finally {
                IOUtils.closeQuietly(keyStoreStream);
            }
        }

        private static final TrustManager dummyTrustManager() {
            return new X509TrustManager() {

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }
            };
        }

        private SSLEngine createSSLEngine(SSLContext sslContext) throws IOException, GeneralSecurityException {
            SSLEngine sslEngine = sslContext.createSSLEngine();
            sslEngine.setUseClientMode(true);
            return sslEngine;
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            ch.pipeline()/**/
            .addLast("ssl", new SslHandler(createSSLEngine(createSSLContext())))/**/
            .addLast("http", new HttpClientCodec())/**/
            .addLast("chunker", new ChunkedWriteHandler())/**/
            .addLast("handler", new MyChannelInboundHandlerAdapter());
        }
    }

    private static class Response {
        private final HttpResponseStatus status;
        private final HttpHeaders headers;
        private final List<byte[]> chunks = new ArrayList<byte[]>();

        public Response(HttpResponse response) {
            this.status = response.getStatus();
            this.headers = response.headers();
        }

        public void chunk(ByteBuf chunk) {
            chunks.add(Utils.byteBuf2bytes(chunk));
        }

        public HttpResponseStatus status() {
            return status;
        }

        public HttpHeaders headers() {
            return headers;
        }

        public String body() {
            if (chunks.isEmpty()) {
                return null;
            } else {
                int size = 0;
                for (byte[] chunk : chunks) {
                    size += chunk.length;
                }
                byte[] bodyBytes = new byte[size];
                int offset = 0;
                for (byte[] chunk : chunks) {
                    System.arraycopy(chunk, 0, bodyBytes, offset, chunk.length);
                    offset += chunk.length;
                }
                return new String(bodyBytes, CharsetUtil.UTF_8);
            }
        }
    }

    @Sharable
    public static final class MyChannelInboundHandlerAdapter extends ChannelInboundHandlerAdapter {

        public static final AttributeKey<Response> RESPONSE = new AttributeKey<Response>("response");
        public static final AttributeKey<ResponseFuture> RESPONSE_FUTURE = new AttributeKey<ResponseFuture>("responseFuture");

        public static Attribute<Response> responseAttr(ChannelPipeline p) {
            return p.context(MyChannelInboundHandlerAdapter.class).attr(RESPONSE);
        }

        public static Attribute<ResponseFuture> responseFutureAttr(ChannelPipeline p) {
            ChannelHandlerContext ctx = p.context(MyChannelInboundHandlerAdapter.class);
            return ctx.attr(RESPONSE_FUTURE);
        }

        @Override
        public void channelRead(final ChannelHandlerContext ctx, Object e) throws Exception {

            ResponseFuture responseFuture = responseFutureAttr(ctx.pipeline()).get();

            if (responseFuture != null) {
                if (e instanceof HttpResponse) {
                    responseAttr(ctx.pipeline()).set(new Response((HttpResponse) e));

                } else if (e instanceof HttpContent) {

                    if (e instanceof LastHttpContent) {
                        // omit trailing headers
                        Response response = responseAttr(ctx.pipeline()).getAndRemove();
                        responseFuture.set(response);
                        responseFutureAttr(ctx.pipeline()).remove();

                    } else {
                        Response response = responseAttr(ctx.pipeline()).get();
                        response.chunk(HttpContent.class.cast(e).content());
                    }
                }
            }
        }
        
        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            
            ResponseFuture responseFuture = responseFutureAttr(ctx.pipeline()).get();
            if (responseFuture != null) {
                responseFuture.set(new RuntimeException("How come the channel was closed?!, How can I properly trap this upstream?"));
            }
            
            ctx.fireChannelInactive();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            ResponseFuture responseFuture = responseFutureAttr(ctx.pipeline()).get();

            if (responseFuture != null) {
                responseFuture.set(cause);
            }

            ctx.fireExceptionCaught(cause);
        }
    }

    static class ResponseFuture implements Future<Response> {
        private final AtomicBoolean done = new AtomicBoolean(false);
        private final AtomicBoolean cancelled = new AtomicBoolean(false);
        private final AtomicReference<Response> responseRef = new AtomicReference<Response>();
        private final AtomicReference<Throwable> exceptionRef = new AtomicReference<Throwable>();
        private CountDownLatch latch = new CountDownLatch(1);

        public void set(Response myOwnFullHttpResponse) {
            // FIXME racy condition
            if (!done.getAndSet(true) && !cancelled.get()) {
                responseRef.set(myOwnFullHttpResponse);
                latch.countDown();
            }
        }

        public void set(Throwable t) {
            // FIXME racy condition
            if (!cancelled.getAndSet(true) && done.compareAndSet(false, true)) {
                exceptionRef.set(t);
                latch.countDown();
            }
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            if (!done.get()) {
                return false;
            } else {
                cancelled.set(true);
                latch.countDown();
                return true;
            }
        }

        @Override
        public boolean isCancelled() {
            return cancelled.get();
        }

        @Override
        public boolean isDone() {
            return done.get();
        }

        @Override
        public Response get() throws InterruptedException {
            latch.await();
            return responseRef.get();
        }

        @Override
        public Response get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            latch.await(timeout, unit);
            Response response = responseRef.get();
            if (response != null) {
                return response;
            } else {
                throw new ExecutionException(exceptionRef.get());
            }
        }
    }

    private ResponseFuture post(Bootstrap b, String url, final String string) throws InterruptedException {

        URI uri = URI.create(url);

        // FIXME handle connect timeout exception
        Channel ch = b.connect(uri.getHost(), uri.getPort()).sync().channel();

        ResponseFuture future = new ResponseFuture();
        MyChannelInboundHandlerAdapter.responseFutureAttr(ch.pipeline()).set(future);

        byte[] bodyBytes = string.getBytes(CharsetUtil.UTF_8);

        HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, uri.getPath(), Unpooled.wrappedBuffer(bodyBytes));
        request.headers()/**/
        .set(HttpHeaders.Names.CONTENT_TYPE, "text/html")/**/
        .set(HttpHeaders.Names.HOST, uri.getHost())/**/
        .set(HttpHeaders.Names.ACCEPT, "*/*")/**/
        .set(HttpHeaders.Names.CONTENT_LENGTH, bodyBytes.length);

        ch.writeAndFlush(request).addListener(new GenericFutureListener<ChannelFuture>() {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception {
                if (!future.isSuccess()) {
                    ResponseFuture responseFuture = MyChannelInboundHandlerAdapter.responseFutureAttr(future.channel().pipeline()).getAndRemove();
                    responseFuture.set(future.cause());
                    MyChannelInboundHandlerAdapter.responseAttr(future.channel().pipeline()).remove();
                }
            }
        });

        return future;
    }

    @Test(groups = { "standalone", "default_provider" })
    public void multipleSSLRequestsTest() throws Throwable {

        EventLoopGroup group = new NioEventLoopGroup();
        Bootstrap b = new Bootstrap().group(group).channel(NioSocketChannel.class).handler(new MyChannelInitializer());
        try {
            String body = "Hello world";
            List<ResponseFuture> futures = new ArrayList<ResponseFuture>();
            for (int i = 0; i < 10; i++) {
                futures.add(post(b, String.format("https://127.0.0.1:%d/foo/test", port), body));
            }

            for (ResponseFuture future : futures) {
                assertEquals(future.get().body(), body);
            }

        } finally {
            group.shutdownGracefully();
        }
    }

    private ResponseFuture post(Bootstrap b, String url, final File file) throws Exception {

        URI uri = URI.create(url);

        // FIXME handle connect timeout exception
        Channel ch = b.connect(uri.getHost(), uri.getPort()).sync().channel();

        ResponseFuture future = new ResponseFuture();
        MyChannelInboundHandlerAdapter.responseFutureAttr(ch.pipeline()).set(future);

        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, uri.getPath());
        request.headers()/**/
        .set(HttpHeaders.Names.CONTENT_TYPE, "text/html")/**/
        .set(HttpHeaders.Names.HOST, uri.getHost())/**/
        .set(HttpHeaders.Names.ACCEPT, "*/*")/**/
        .set(HttpHeaders.Names.CONTENT_LENGTH, file.length());

        ch.writeAndFlush(request);
        RandomAccessFile raf = new RandomAccessFile(file, "r");
        ch.write(new ChunkedFile(raf, 0, file.length(), 8 * 1024))/**/
        // FIXME DefaultFileRegion not working over HTTPS?
        // ch.write(new DefaultFileRegion(raf.getChannel(), 0, file.length()))/**/
                .addListener(new GenericFutureListener<ChannelFuture>() {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        if (!future.isSuccess()) {
                            ResponseFuture responseFuture = MyChannelInboundHandlerAdapter.responseFutureAttr(future.channel().pipeline()).getAndRemove();
                            responseFuture.set(future.cause());
                            MyChannelInboundHandlerAdapter.responseAttr(future.channel().pipeline()).remove();
                        }
                    }
                });

        ch.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);

        return future;
    }

    @Test(groups = { "standalone", "default_provider" })
    public void zeroCopyPostTest() throws Throwable {

        EventLoopGroup group = new NioEventLoopGroup();
        Bootstrap b = new Bootstrap().group(group).channel(NioSocketChannel.class).handler(new MyChannelInitializer());
        try {
            ResponseFuture future = post(b, String.format("https://127.0.0.1:%d/foo/test", port), SIMPLE_TEXT_FILE);
            assertEquals(future.get(TIMEOUT, TimeUnit.SECONDS).body(), "This is a simple test file");

        } finally {
            group.shutdownGracefully();
        }
    }

    private static final class Utils {

        public static int findFreePort() throws IOException {
            ServerSocket socket = null;

            try {
                socket = new ServerSocket(0);

                return socket.getLocalPort();
            } finally {
                if (socket != null) {
                    socket.close();
                }
            }
        }

        public static byte[] byteBuf2bytes(ByteBuf b) {
            int readable = b.readableBytes();
            int readerIndex = b.readerIndex();
            if (b.hasArray()) {
                byte[] array = b.array();
                if (b.arrayOffset() == 0 && readerIndex == 0 && array.length == readable) {
                    return array;
                }
            }
            byte[] array = new byte[readable];
            b.getBytes(readerIndex, array);
            return array;
        }
    }
}
