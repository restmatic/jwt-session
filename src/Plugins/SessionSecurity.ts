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
    jwtSecret: 'changeMe',
    jwtSigningOptions: {},
    jwtVerifyOptions: {}
  })
  .hooks({
    load: async (Injector, PluginLogger, PluginVariables, PluginFiles, Authentication) => {
      PluginLogger.log('Creating SessionSecurity methods', 1)
      return {
        encodeJwt: (data, overrideOpts?) => {
          const opts = overrideOpts || PluginVariables.jwtSigningOptions
          return new Promise((resolve, reject) => {
            sign(data, PluginVariables.jwtSecret, opts, (err, token) => {
              if(err){
                return reject(err)
              }
              return resolve(token)
            })
          })
        },
        decodeJwt: (token, overrideOpts?) => {
          const opts = overrideOpts || PluginVariables.jwtVerifyOptions
          return new Promise((resolve, reject) => {
            verify(token, PluginVariables.jwtSecret, opts,(err, payload) => {
              if(err){
                return reject(err)
              }
              return resolve(payload)
            })
          })

        }
      }
    }

  })