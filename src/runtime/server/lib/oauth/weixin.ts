import type { H3Event } from 'h3'
import { eventHandler, getQuery, sendRedirect, createError } from 'h3'
import { withQuery } from 'ufo'
import { defu } from 'defu'
import { getOAuthRedirectURL, handleAccessTokenErrorResponse, handleInvalidState, handleMissingConfiguration, handleState, requestAccessToken } from '../utils'
import { useRuntimeConfig } from '#imports'
import type { OAuthConfig } from '#auth-utils'

export interface OAuthWeixinConfig {
  /**
   * Weixin OAuth Client ID (AppID)
   * @default process.env.NUXT_OAUTH_WEIXIN_CLIENT_ID
   */
  clientId?: string
  /**
   * Weixin OAuth Client Secret (AppSecret)
   * @default process.env.NUXT_OAUTH_WEIXIN_CLIENT_SECRET
   */
  clientSecret?: string

  /**
   * Weixin OAuth Authorization URL
   * @default 'https://open.weixin.qq.com/connect/qrconnect'
   */
  authorizationURL?: string

  /**
   * Weixin OAuth Token URL
   * @default 'https://api.weixin.qq.com/sns/oauth2/access_token'
   */
  tokenURL?: string

  /**
   * Weixin User Info URL
   * @default 'https://api.weixin.qq.com/sns/userinfo'
   */
  userInfoURL?: string

  /**
   * Redirect URL to allow overriding for situations like prod failing to determine public hostname
   * @default process.env.NUXT_OAUTH_WEIXIN_REDIRECT_URL
   */
  redirectURL?: string

  /**
   * Weixin OAuth Scope
   * @default 'snsapi_login'
   * @see https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
   */
  scope?: string

  /**
   * Extra authorization parameters to provide to the authorization URL
   */
  authorizationParams?: Record<string, string>
}

interface WeixinTokens {
  access_token: string
  expires_in: number
  refresh_token: string
  openid: string
  scope: string
  unionid?: string
}

interface WeixinUser {
  openid: string
  nickname: string
  sex: number
  province: string
  city: string
  country: string
  headimgurl: string
  privilege: string[]
  unionid?: string
}

export function defineOAuthWeixinEventHandler({ config, onSuccess, onError }: OAuthConfig<OAuthWeixinConfig, { user: WeixinUser, tokens: WeixinTokens }>) {
  return eventHandler(async (event: H3Event) => {
    config = defu(config, useRuntimeConfig(event).oauth?.weixin, {
      authorizationURL: 'https://open.weixin.qq.com/connect/qrconnect',
      tokenURL: 'https://api.weixin.qq.com/sns/oauth2/access_token',
      userInfoURL: 'https://api.weixin.qq.com/sns/userinfo',
      scope: 'snsapi_login',
      authorizationParams: {},
    }) as OAuthWeixinConfig

    const query = getQuery<{ code?: string, error?: string, state?: string }>(event)

    if (query.error) {
      const error = createError({
        statusCode: 401,
        message: `Weixin login failed: ${query.error || 'Unknown error'}`,
        data: query,
      })
      if (!onError) throw error
      return onError(event, error)
    }

    if (!config.clientId || !config.clientSecret) {
      return handleMissingConfiguration(event, 'weixin', ['clientId', 'clientSecret'], onError)
    }

    const redirectURL = config.redirectURL || getOAuthRedirectURL(event)
    const state = await handleState(event)

    if (!query.code) {
      return sendRedirect(
        event,
        withQuery(config.authorizationURL as string, {
          appid: config.clientId,
          redirect_uri: redirectURL,
          response_type: 'code',
          scope: config.scope || 'snsapi_login',
          state,
          ...config.authorizationParams,
        }) + '#wechat_redirect',
      )
    }

    if (query.state !== state) {
      return handleInvalidState(event, 'weixin', onError)
    }

    const tokens = JSON.parse(await requestAccessToken(config.tokenURL as string, {
      params: {
        appid: config.clientId,
        secret: config.clientSecret,
        code: query.code,
        grant_type: 'authorization_code',
      },
    }))

    if (tokens.errmsg) {
      return handleAccessTokenErrorResponse(event, 'weixin', tokens, onError)
    }

    const accessToken = tokens.access_token
    const openid = tokens.openid

    if (!accessToken || !openid) {
      const error = createError({
        statusCode: 500,
        message: 'Could not get Weixin access token or openid',
        data: tokens,
      })
      if (!onError) throw error
      return onError(event, error)
    }

    // Get user info
    const user = await $fetch<WeixinUser>(config.userInfoURL as string, {
      params: {
        access_token: accessToken,
        openid: openid,
        lang: 'zh_CN',
      },
    })

    return onSuccess(event, {
      user,
      tokens,
    })
  })
}
