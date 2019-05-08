/**
 * @file SessionSecurity
 * @author Jim Bulkowski <jim.b@paperelectron.com>
 * @project jwt-session
 * @license MIT {@link http://opensource.org/licenses/MIT}
 */

import {CreatePlugin} from "@pomegranate/plugin-tools";
import {sign, verify} from 'jsonwebtoken'

export const SessionSecurity = CreatePlugin('merge')
  .configuration({
    name: 'SessionSecurity',
    injectableParam: 'RouteSecurity',
    injectableScope: 'global',
    depends: ['@restmatic/AuthenticationCore', '@restmatic/RouteSecurity'],
    provides: ['@restmatic/Core']
  })
  .variables({
    jwtSecret: 'changeMe'
  })
  .hooks({
    load: async (Injector, PluginLogger, PluginVariables, PluginFiles, Authentication) => {
      PluginLogger.log('Creating SessionSecurity methods', 1)
      return {
        encodeJwt: (data) => {
          return sign(data, PluginVariables.jwtSecret)
        },
        decodeJwt: (token, cb) => {
          return verify(token, PluginVariables.jwtSecret, cb)
        }
      }
    }

  })