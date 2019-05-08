/**
 * @file AuthMiddleware
 * @author Jim Bulkowski <jim.b@paperelectron.com>
 * @project Authentication
 * @license MIT {@link http://opensource.org/licenses/MIT}
 */
import {CreatePlugin} from "@pomegranate/plugin-tools";
import expressJwt from 'express-jwt';
import cookies from 'cookie-parser'

export const SessionMiddleware = CreatePlugin('merge')
  .configuration({
    name: 'SessionMiddleware',
    injectableParam: 'Middleware',
    injectableScope: 'namespace',
    depends: ['@restmatic/Core', '@restmatic/Strategies'],
    provides: ['@restmatic/Middleware']
  })
  .hooks({
    load: async (Injector, PluginLogger, Authentication, RouteSecurity, JWTuser) => {
      PluginLogger.log('Creating Session Middleware.', 1)

      return {
        cookies: cookies(),
        JWTSession: (req, res, next) => {
          if (req.headers.authorization) {
            return Authentication.authenticate('bearer', {session: false}, function (err, user, info) {
              if (err) {
                return next(err)
              }
              if (!user) {
                return next()
              }
              if (user && user.uuid) {
                return req.user = JWTuser(user, next)
                // return req.user = {}
              }
              //req.user = user

              return next()

            })(req, res, next);
          } else if (req.cookies.jwt_token) {
            return RouteSecurity.decodeJwt(req.cookies.jwt_token, function (err, user) {
              if (user && user.uuid) {
                let u = JWTuser(user, next)
                return req.user = u
              }
              return next()
            })
            //return handleCookieJWT(req, res, next);
          } else {
            return next()
          }

        }
      }
    }

  })