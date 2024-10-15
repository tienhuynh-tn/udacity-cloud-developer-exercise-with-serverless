import jsonwebtoken from 'jsonwebtoken'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJJp10Q4l24D5eMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGXRpZW5odXluaC10bi5hdS5hdXRoMC5jb20wHhcNMjQxMDE1MDgyOTExWhcN
MzgwNjI0MDgyOTExWjAkMSIwIAYDVQQDExl0aWVuaHV5bmgtdG4uYXUuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1cstSp48zt1qtWNV
BBb0b2q997aObzuU/VXPXGXfBMU/u5FlTbFC52o6Ppdx2wGqfcRZKWT6NrXNrQyh
p/m8/QVOD0pu4smvNadNVAfzCLstRbYA1i79VB8P+Jv8oM9cOWHvBllc0BvSaEzb
/5suyL6NA4BJXxLItMwZA95oL6lxN12ADPpH3tko9bk7tgIbMdQ2zHQhmslZIT3w
487v+3le1mlv5r7Uu2KF7qMAXPuw/P7eqBYxyermaAe0Up1JI9f65pIEV+qzqqDH
RVyWJBvCm8Oj0vdwsPYFGCY+xjrSFiUQ696NFCsmQyaXUS4IGEF+llDTG6QsTQqO
RjWLzQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTJX/6Fau+u
A4l3688XlA5cd5CL5TAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AFuOZKBC/2x/v0WUJAPtR8++1gJ7VXXmB42LnqESZL+Gkj94IAEWUArU/UfTvKt9
Jhqaw8hpBmxk2c9DIrl/bWYrLAqyjLLReBFjki2BAoOlHm9Xy7BKDqAV9F4I2t8S
vycm+tJ5P3HD4kHdBTAD9oLOkGScAAsayur/EOlvtuxQJrzTy1bdUzV/A2SeyMeU
Sg3doAsqlR8XJL6/1JKHdCl44NPS63egpUwiBHraV9aSwRgWY/x2lu6NkdHrpQNW
94nHGCWibBDD4Vua92460EUrwxbxEmv9uNrHeYVMLhT7x9EVXPCsephQxZV71CEW
RTe8C0K9BkrDB9tdcYoL6WM=
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User was not authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader) {
  if (!authHeader) throw new Error('No authorization header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authorization header')

  const split = authHeader.split(' ')
  const token = split[1]

  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
}