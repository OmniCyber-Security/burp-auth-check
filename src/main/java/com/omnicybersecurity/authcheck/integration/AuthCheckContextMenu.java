package com.omnicybersecurity.authcheck.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.omnicybersecurity.authcheck.engine.AuthCheckEngine;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Adds "Send to Auth Check" wherever Burp offers a context menu on requests, so
 * a tester can aim the extension at one specific request without turning on
 * automatic testing of everything.
 */
public final class AuthCheckContextMenu implements ContextMenuItemsProvider {

    private final AuthCheckEngine engine;
    private final Consumer<Void> focusTab;

    public AuthCheckContextMenu(AuthCheckEngine engine, Consumer<Void> focusTab) {
        this.engine = engine;
        this.focusTab = focusTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collect(event);
        if (selected.isEmpty()) {
            return List.of();
        }

        String suffix = selected.size() == 1 ? "" : " (" + selected.size() + " requests)";
        JMenuItem test = new JMenuItem("Send to Auth Check" + suffix);
        test.addActionListener(e -> {
            engine.submitManual(selected);
            focusTab.accept(null);
        });

        return List.of(test);
    }

    private static List<HttpRequestResponse> collect(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
        if (selected.isEmpty()) {
            Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
            if (editor.isPresent()) {
                selected.add(editor.get().requestResponse());
            }
        }
        // A request with no response can still be tested; the baseline just does
        // not establish what authorised access looks like, and the record says so.
        selected.removeIf(exchange -> exchange == null || exchange.request() == null);
        return selected;
    }
}
