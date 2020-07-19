/**
 * @file AuthMiddleware
 * @author Jim Bulkowski <jim.b@paperelectron.com>
 * @project Authentication
 * @license MIT {@link http://opensource.org/licenses/MIT}
 */
import {CreatePlugin} from "@pomegranate/plugin-tools";
import expressJwt from 'express-jwt';
import cookies from 'cookie-parser'
import {JsonWebTokenError} from "jsonwebtoken";

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
        JWTSession: async (req, res, next) => {
          if (req.headers.authorization) {
            return Authentication.authenticate('bearer', {session: false}, function (err, user, info) {
              if (err) {
                err.defaultStatusCode = 401
                return next(err)
              }
              if (!user) {
                return next()
              }
              if (user && user.uuid) {
                return req.user = JWTuser(user, next)
              }
              return next()

            })(req, res, next);

          } else if (req.cookies.jwt_token) {
            try {
              let user = await RouteSecurity.decodeJwt(req.cookies.jwt_token)
              if(user && user.uuid){
                return req.user = JWTuser(user, next)
              }
              throw new Error('Decoded token did not contain a user or user.uuid')
            }
            catch(err){
              PluginLogger.error(err.message)
              next()
            }
          } else {
            return next()
          }

        }
      }
    }

  })