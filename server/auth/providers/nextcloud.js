// @flow
import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import { Strategy as NextcloudStrategy } from "passport-nextcloud";
import accountProvisioner from "../../commands/accountProvisioner";
import env from "../../env";
import auth from "../../middlewares/authentication";
import passportMiddleware from "../../middlewares/passport";
import {
  IntegrationAuthentication,
  Collection,
  Integration,
  Team,
} from "../../models";
import { StateStore } from "../../utils/passport";

const router = new Router();
const providerName = "nextcloud";
const NEXTCLOUD_APP_ID = process.env.NEXTCLOUD_APP_ID;
const NEXTCLOUD_APP_SECRET = process.env.NEXTCLOUD_APP_SECRET;
const NEXTCLOUD_BASE_URL = process.env.NEXTCLOUD_BASE_URL;
const NEXTCLOUD_AVATAR_URL = process.env.NEXTCLOUD_AVATAR_URL;

const scopes = [
  "identity.email",
  "identity.basic",
  "identity.avatar",
  "identity.team",
];

export const config = {
  name: "NextCloud",
  enabled: !!NEXTCLOUD_APP_ID,
};

if (NEXTCLOUD_APP_ID) {
  const strategy = new NextcloudStrategy(
    {
      clientID: NEXTCLOUD_APP_ID,
      clientSecret: NEXTCLOUD_APP_SECRET,
      baseURL: NEXTCLOUD_BASE_URL,
    },
    function (accessToken, refreshToken, profile, done) {
      console.log("verified success:" + accessToken);
      console.log(profile);
      accountProvisioner({
        ip: "localhost",
        team: {
          name: profile.username,
          domain: NEXTCLOUD_BASE_URL,
          subdomain: NEXTCLOUD_BASE_URL,
          avatarUrl: NEXTCLOUD_AVATAR_URL,
        },
        user: {
          name: profile.username,
          email: profile.emails[0]?.value,
          avatarUrl: NEXTCLOUD_AVATAR_URL,
        },
        authenticationProvider: {
          name: providerName,
          providerId: profile.id,
        },
        authentication: {
          providerId: profile.id,
          accessToken,
          refreshToken,
          scopes,
        },
      })
        .then((result) => {
          done(null, result.user, result);
        })
        .catch((err) => {
          console.error(err.stack || err);
          done(err, null);
        });
    }
  );
  strategy.name = providerName;
  passport.use(strategy);

  router.get("nextcloud", passport.authenticate(providerName));

  router.get("nextcloud.callback", passportMiddleware(providerName));

  router.get("nextcloud.post", auth({ required: false }), async (ctx) => {
    const { code, error, state } = ctx.request.query;
    const user = ctx.state.user;
    ctx.assertPresent(code || error, "code is required");

    const collectionId = state;
    ctx.assertUuid(collectionId, "collectionId must be an uuid");

    if (error) {
      ctx.redirect(`/settings/integrations/nextcloud?error=${error}`);
      return;
    }
  });
}

export default router;
