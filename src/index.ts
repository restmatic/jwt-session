/**
 * @file index
 * @author Jim Bulkowski <jim.b@paperelectron.com>
 * @project Authentication
 * @license MIT {@link http://opensource.org/licenses/MIT}
 */

import {CreatePlugin} from '@pomegranate/plugin-tools'
import {SessionMiddleware} from "./Plugins/SessionMiddleware";
import {SessionSecurity} from "./Plugins/SessionSecurity";
import {JWTuser} from "./Plugins/JWTuser";


export const Plugin = CreatePlugin('application')
.configuration({
  name: 'JWTSession',
})
.applicationPlugins([
  SessionMiddleware,
  SessionSecurity,
  JWTuser
])