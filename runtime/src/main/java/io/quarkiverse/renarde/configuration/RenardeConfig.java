package io.quarkiverse.renarde.configuration;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;

@ConfigMapping(prefix = "quarkus.renarde")
@ConfigRoot(phase = ConfigPhase.BUILD_AND_RUN_TIME_FIXED)
public interface RenardeConfig {

    /**
     * Renarde Auth config
     */
    public RenardeAuthConfig auth();

    public interface RenardeAuthConfig {

        /**
         * Whether the quarkus.renarde.auth.location-cookie is enabled.
         */
        @WithDefault("true")
        @WithName("location-cookie.enabled")
        public boolean locationCookieEnabled();

        /**
         * Option to control the name of the cookie used to redirect the user back
         * to where he wants to get access to.
         */
        @WithDefault("quarkus-redirect-location")
        public String locationCookie();

        /**
         * Option to control the name of the redirect query param used to redirect the user back
         * to where he wants to get access to.
         */
        @WithDefault("redirect_uri")
        public String redirectQueryParam();

    }
}
