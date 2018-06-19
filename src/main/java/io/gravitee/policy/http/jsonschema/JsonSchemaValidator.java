/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.http.jsonschema;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.core.report.ProcessingReport;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.github.fge.jsonschema.main.JsonValidator;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.http.jsonschema.configuration.JsonSchemaValidatorPolicyConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class JsonSchemaValidator {

    private final static Logger logger = LoggerFactory.getLogger(JsonSchemaValidator.class);

    public static final String CONTENT_TYPE = "application/json";

    private JsonSchemaValidatorPolicyConfiguration configuration;

    private static final JsonValidator validator =  JsonSchemaFactory.byDefault().getValidator();

    public JsonSchemaValidator(JsonSchemaValidatorPolicyConfiguration jsonSchemaValidatorPolicyConfiguration) {
        this.configuration = jsonSchemaValidatorPolicyConfiguration;
    }

    @OnRequestContent
    public ReadWriteStream onRequestContent(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        logger.debug("Execute json schema validation policy on request {}", request.id());
        return new BufferedReadWriteStream() {

            Buffer buffer = Buffer.buffer();

            @Override
            public SimpleReadWriteStream<Buffer> write(Buffer content) {
                buffer.appendBuffer(content);
                return this;
            }

            @Override
            public void end() {
                try {
                    JsonNode schema = JsonLoader.fromString(configuration.getJsonSchema());
                    JsonNode content = JsonLoader.fromString(buffer.toString());

                    ProcessingReport report;

                    if (configuration.isValidateUnchecked()) {
                        report = validator.validateUnchecked(schema, content, configuration.isDeepCheck());
                    } else {
                        report = validator.validate(schema, content, configuration.isDeepCheck());
                    }

                    if (!report.isSuccess()) {
                        request.metrics().setMessage(report.toString());
                        String errorMessage = executionContext.getTemplateEngine().convert(configuration.getErrorMessage());
                        policyChain.streamFailWith(PolicyResult.failure(HttpStatusCode.BAD_REQUEST_400, errorMessage, CONTENT_TYPE));
                    } else {
                        super.write(buffer);
                        super.end();
                    }
                } catch (Exception ex) {
                    request.metrics().setMessage(ex.getMessage());
                    String errorMessage = executionContext.getTemplateEngine().convert(configuration.getErrorMessage());
                    policyChain.streamFailWith(PolicyResult.failure(HttpStatusCode.BAD_REQUEST_400, errorMessage, CONTENT_TYPE));
                }
            }
        };
    }

}
