/**
 *  Copyright 2005-2016 Red Hat, Inc.
 *
 *  Red Hat licenses this file to you under the Apache License, version
 *  2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.  See the License for the specific language governing
 *  permissions and limitations under the License.
 */
package com.eb.test;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.cxf.Bus;
import org.apache.cxf.common.classloader.ClassLoaderUtils;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.feature.LoggingFeature;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.jaxrs.swagger.Swagger2Feature;
import org.apache.cxf.rs.security.httpsignature.MessageSigner;
import org.apache.cxf.rs.security.httpsignature.MessageVerifier;
import org.apache.cxf.rs.security.httpsignature.filters.CreateSignatureInterceptor;
import org.apache.cxf.rs.security.httpsignature.filters.VerifySignatureClientFilter;
import org.apache.cxf.rs.security.httpsignature.filters.VerifySignatureFilter;
import org.apache.cxf.rs.security.httpsignature.provider.KeyProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.boot.autoconfigure.web.ErrorMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;

@SpringBootApplication(scanBasePackages = "com.eb.test")
//@EnableAutoConfiguration(exclude = {ErrorMvcAutoConfiguration.class})
public class SampleRestApplication {

    @Autowired
    private Bus bus;

    public static void main(String[] args) {
        SpringApplication.run(SampleRestApplication.class, args);
    }
 
    @Bean
    public Server rsServer() {
        // setup CXF-RS
        JAXRSServerFactoryBean endpoint = new JAXRSServerFactoryBean();
        List<Object> providers = new ArrayList<>();

        CreateSignatureInterceptor signatureFilter = new CreateSignatureInterceptor();
        VerifySignatureFilter verifySignatureFilter = new VerifySignatureFilter();

        try {


            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(ClassLoaderUtils.getResourceAsStream("keystore.jks", this.getClass()),
                    "pw".toCharArray());

            Certificate certificate = keyStore.getCertificate("signing-demo");
            PrivateKey privateKey = (PrivateKey)keyStore.getKey("signing-demo", "pw".toCharArray());

            MessageVerifier messageVerifier = new MessageVerifier(keyId -> certificate.getPublicKey());
            verifySignatureFilter.setMessageVerifier(messageVerifier);
            verifySignatureFilter.setEnabled(true);

            MessageSigner messageSigner = new MessageSigner(keyId -> privateKey, "signing-demo-v1");
            signatureFilter.setMessageSigner(messageSigner);
        }
        catch(Exception e) {

        }

        providers.add(new CreateSignatureInterceptor());
        providers.add(new VerifySignatureClientFilter());

        LoggingInInterceptor loggingInInterceptor = new LoggingInInterceptor();
        LoggingOutInterceptor loggingOutInterceptor = new LoggingOutInterceptor();

        endpoint.setInFaultInterceptors(Collections.singletonList(loggingInInterceptor));
        endpoint.setInInterceptors(Collections.singletonList(loggingInInterceptor));

        endpoint.setOutFaultInterceptors(Collections.singletonList(loggingOutInterceptor));
        endpoint.setInInterceptors(Collections.singletonList(loggingOutInterceptor));

        bus.setFeatures(Collections.singleton(new LoggingFeature()));
        endpoint.setProvider(verifySignatureFilter);
        endpoint.setBus(bus);
        endpoint.setServiceBeans(Arrays.<Object>asList(new HelloServiceImpl()));
        endpoint.setAddress("/");
        endpoint.setFeatures(Arrays.asList(new Swagger2Feature()));
        return endpoint.create();
    }
}
