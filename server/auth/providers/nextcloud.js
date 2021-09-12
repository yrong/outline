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
  const strategy = new NextcloudStrategy({
      clientID: NEXTCLOUD_APP_ID,
      clientSecret: NEXTCLOUD_APP_SECRET,
      baseURL: NEXTCLOUD_BASE_URL,
      callbackURL: `http://localhost:3000/auth/nextcloud/callback`,
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(accessToken);
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
