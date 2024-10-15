import { Auth0Provider } from '@auth0/auth0-react'
import React from 'react'
import ReactDOM from 'react-dom'
import 'semantic-ui-css/semantic.min.css'
import App from './App'
import './index.css'

const domain = process.env.REACT_APP_AUTH0_DOMAIN
const clientId = process.env.REACT_APP_AUTH0_CLIENT_ID

console.log("Client ID: ", clientId)

ReactDOM.render(
    <Auth0Provider
      domain={domain}
      clientId={clientId}
      redirectUri="http://localhost:3000"
      audience={`https://${domain}/api/v2/`}
      scope="read:groups write:groups read:images write:images"
    >
      <App />
    </Auth0Provider>,
    document.getElementById('root')
  )