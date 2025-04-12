package com.madneal.cookiecenter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class CustomRequestEditorTab implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("Serialized input editor");

        api.userInterface().registerHttpRequestEditorProvider(new MyHttpRequestEditorProvider(api));
    }
}
