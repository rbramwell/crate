/*
 * Licensed to CRATE Technology GmbH ("Crate") under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  Crate licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * However, if you have executed another commercial license
 * agreement with Crate these terms will supersede the license
 * and you may use the software solely pursuant to the terms of
 * the relevant commercial agreement.
 */

package io.crate.rest.action.admin;

import com.google.common.collect.ImmutableMap;
import io.crate.rest.CrateRestMainAction;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.FileSystemUtils;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.rest.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestStatus.*;

/**
 * RestHandlerAction to return a html page containing informations about crate
 */
public class AdminUIFrontpageAction extends BaseRestHandler {

    private static final Pattern USER_AGENT_BROWSER_PATTERN = Pattern.compile("(Mozilla|Chrome|Safari|Opera|Android|AppleWebKit)+?[/\\s][\\d.]+");
    private final CrateRestMainAction crateRestMainAction;
    private final RestController controller;
    private final Environment environment;

    private final AdminUIRequestFilter requestFilter = new AdminUIRequestFilter();

    @Inject
    public AdminUIFrontpageAction(CrateRestMainAction crateRestMainAction, Settings settings, Client client, RestController controller, Environment environment) {
        super(settings, controller, client);
        this.crateRestMainAction = crateRestMainAction;
        this.controller = controller;
        this.environment = environment;
    }

    public void registerHandler() {
        controller.registerHandler(GET, "/", this);
        controller.registerHandler(GET, "/admin", this);
        controller.registerFilter(requestFilter);
    }

    @Override
    protected void handleRequest(RestRequest request, RestChannel channel, Client client) throws Exception {
        if (!isBrowser(request.header("user-agent"))){
            crateRestMainAction.handleRequest(request, channel, client);
            return;
        }

        if (request.header("accept") != null &&  request.header("accept").contains("application/json")){
            crateRestMainAction.handleRequest(request, channel, client);
            return;
        }

        BytesRestResponse resp = new BytesRestResponse(RestStatus.TEMPORARY_REDIRECT);
        resp.addHeader("Location", "/admin/");
        channel.sendResponse(resp);
    }

    private boolean isBrowser(String headerValue) {
        if (headerValue == null){
            return false;
        }
        String engine = headerValue.split("\\s+")[0];
        Matcher matcher = USER_AGENT_BROWSER_PATTERN.matcher(engine);

        return matcher.matches();
    }

    private class AdminUIRequestFilter extends RestFilter {

        @Override
        public void process(RestRequest request, RestChannel channel, RestFilterChain filterChain) throws IOException {
            if(request.rawPath().startsWith("/admin/")) {
                serveSite(request, channel);
            }
            filterChain.continueProcessing(request, channel);
        }
    }

    private void serveSite(RestRequest request, RestChannel channel) throws IOException {
        if (request.method() == RestRequest.Method.OPTIONS) {
            // when we have OPTIONS request, simply send OK by default (with the Access Control Origin header which gets automatically added)
            channel.sendResponse(new BytesRestResponse(OK));
            return;
        }
        if (request.method() != RestRequest.Method.GET) {
            channel.sendResponse(new BytesRestResponse(FORBIDDEN));
            return;
        }

        String sitePath = request.rawPath().substring("/admin/".length());

        // we default to index.html, or what the plugin provides (as a unix-style path)
        // this is a relative path under _site configured by the plugin.
        if (sitePath.length() == 0) {
            sitePath = "index.html";
        } else {
            // remove extraneous leading slashes, its not an absolute path.
            while (sitePath.length() > 0 && sitePath.charAt(0) == '/') {
                sitePath = sitePath.substring(1);
            }
        }
        final Path siteFile = environment.pluginsFile().resolve("crate-admin").resolve("_site");

        final String separator = siteFile.getFileSystem().getSeparator();
        // Convert file separators.
        sitePath = sitePath.replace("/", separator);

        Path file = siteFile.resolve(sitePath);

        // return not found instead of forbidden to prevent malicious requests to find out if files exist or dont exist
        if (!Files.exists(file) || FileSystemUtils.isHidden(file) || !file.toAbsolutePath().normalize().startsWith(siteFile.toAbsolutePath().normalize())) {
            channel.sendResponse(new BytesRestResponse(NOT_FOUND));
            return;
        }

        BasicFileAttributes attributes = Files.readAttributes(file, BasicFileAttributes.class);
        if (!attributes.isRegularFile() && !attributes.isDirectory()) {
            // If it's not a dir, we send a 403
            channel.sendResponse(new BytesRestResponse(FORBIDDEN));
            return;
        }

        try {
            byte[] data = Files.readAllBytes(file);
            channel.sendResponse(new BytesRestResponse(OK, guessMimeType(sitePath), data));
        } catch (IOException e) {
            channel.sendResponse(new BytesRestResponse(INTERNAL_SERVER_ERROR));
        }
    }

    private String guessMimeType(String path) {
        int lastDot = path.lastIndexOf('.');
        if (lastDot == -1) {
            return "";
        }
        String extension = path.substring(lastDot + 1).toLowerCase(Locale.ROOT);
        String mimeType = DEFAULT_MIME_TYPES.get(extension);
        if (mimeType == null) {
            return "";
        }
        return mimeType;
    }

    private static final Map<String, String> DEFAULT_MIME_TYPES;

    static {
        // This is not an exhaustive list, just the most common types. Call registerMimeType() to add more.
        Map<String, String> mimeTypes = new HashMap<>();
        mimeTypes.put("txt", "text/plain");
        mimeTypes.put("css", "text/css");
        mimeTypes.put("csv", "text/csv");
        mimeTypes.put("htm", "text/html");
        mimeTypes.put("html", "text/html");
        mimeTypes.put("xml", "text/xml");
        mimeTypes.put("js", "text/javascript"); // Technically it should be application/javascript (RFC 4329), but IE8 struggles with that
        mimeTypes.put("xhtml", "application/xhtml+xml");
        mimeTypes.put("json", "application/json");
        mimeTypes.put("pdf", "application/pdf");
        mimeTypes.put("zip", "application/zip");
        mimeTypes.put("tar", "application/x-tar");
        mimeTypes.put("gif", "image/gif");
        mimeTypes.put("jpeg", "image/jpeg");
        mimeTypes.put("jpg", "image/jpeg");
        mimeTypes.put("tiff", "image/tiff");
        mimeTypes.put("tif", "image/tiff");
        mimeTypes.put("png", "image/png");
        mimeTypes.put("svg", "image/svg+xml");
        mimeTypes.put("ico", "image/vnd.microsoft.icon");
        mimeTypes.put("mp3", "audio/mpeg");
        DEFAULT_MIME_TYPES = ImmutableMap.copyOf(mimeTypes);
    }

}
