import { catchErrors } from '@kkapoor/utils';
import { __DEV__ } from '@kkapoor/utils/constants';
import * as Jose from 'jose';
import { nanoid } from 'nanoid';
import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import 'server-only';
import { deepMerge } from './utils';

const __PROD__ = !__DEV__;

export type DefaultCookieOptions = BetterOmit<CookieOptions, 'value' | 'name'>;
export type TokenType = 'access' | 'refresh';
export type TokenConfig = {
    cookieName?: string;
    maxAge?: number;
    secret?: string;
    actions: Record<'sign' | 'refresh', string>;
};

export type CookieOptions = {
    path: string;
    priority: 'low' | 'medium' | 'high';
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'strict' | 'lax' | 'none';
    name: string;
    value: string;
};

export type BetterOmit<T extends object, K extends keyof T> = {
    [Key in Exclude<keyof T, K>]: T[Key];
};

export type TokenAction = `${TokenType}.${string}`;

export type ClientConfig<TPayload> = {
    routes: {
        protected: string[];
        public: string[];
    };
    tokenConfig: Record<TokenType, TokenConfig>;
    defaultCookieOptions?: Partial<DefaultCookieOptions>;
    genSessionId?(): Promise<string>;
    redirects: {
        auth: string;
        noAuth: string;
    };
};

export type NestedNonNullable<T extends object> = {
    [K in keyof T]-?: T[K] extends object
        ? NestedNonNullable<T[K]>
        : NonNullable<T[K]>;
};

class NextJoseAuthClient<TPayload extends Record<string, any>> {
    public static DEFAULT_COOKIE_OPTIONS: DefaultCookieOptions = {
        httpOnly: true,
        secure: true,
        path: '/',
        sameSite: 'lax',
        priority: 'high',
    };

    public static DEFAULT_VARIABLE_COOKIE_OPTIONS = {
        access: {
            cookieName: process.env['ACCESS_TOKEN_COOKIE_NAME']!,
            maxAge: process.env['ACCESS_TOKEN_COOKIE_MAX_AGE']
                ? parseFloat(process.env['ACCESS_TOKEN_COOKIE_MAX_AGE'])
                : undefined,
            secret: process.env['ACCESS_TOKEN_SECRET']!,
        },
        refresh: {
            cookieName: process.env['REFRESH_TOKEN_COOKIE_NAME']!,
            maxAge: process.env['REFRESH_TOKEN_COOKIE_MAX_AGE']
                ? parseFloat(process.env['REFRESH_TOKEN_COOKIE_MAX_AGE'])
                : undefined,
            secret: process.env['REFRESH_TOKEN_SECRET']!,
        },
    };

    private static secretEncoder = new TextEncoder();

    private protectedRoutes: string[];
    private publicRoutes: string[];

    public tokenConfig: NestedNonNullable<
        ClientConfig<TPayload>['tokenConfig']
    >;

    private redirects: ClientConfig<TPayload>['redirects'];

    private genSessionId = async () => nanoid();

    constructor(config: ClientConfig<TPayload>) {
        const {
            routes,
            defaultCookieOptions,
            tokenConfig,
            genSessionId,
            redirects,
        } = config;

        NextJoseAuthClient.DEFAULT_COOKIE_OPTIONS = {
            ...NextJoseAuthClient.DEFAULT_COOKIE_OPTIONS,
            ...(defaultCookieOptions ?? {}),
        };

        this.tokenConfig = deepMerge(
            tokenConfig,
            NextJoseAuthClient.DEFAULT_VARIABLE_COOKIE_OPTIONS
        ) as any;

        this.protectedRoutes = routes.protected;
        this.publicRoutes = routes.public;

        if (genSessionId) this.genSessionId = genSessionId;

        this.redirects = redirects;
    }

    public async signToken<T extends TokenType>(type: T, payload: TPayload) {
        const { actions, maxAge, secret, cookieName } = this.tokenConfig[type];

        const tokenExp = new Date(Date.now() + maxAge * 1000);
        const sessionId = await this.genSessionId();

        const token = await new Jose.SignJWT(payload)
            .setExpirationTime(tokenExp)
            .setIssuedAt()
            .setJti(sessionId)
            .setProtectedHeader({ alg: 'HS256' })
            .setSubject(actions.sign)
            .sign(NextJoseAuthClient.secretEncoder.encode(secret));

        return {
            ...NextJoseAuthClient.DEFAULT_COOKIE_OPTIONS,
            name: cookieName,
            value: token,
        };
    }

    public async verifyToken<T extends TokenType>(
        type: T,
        token: string | undefined
    ) {
        if (!token) throw new Error(`${type} token undefined.`);

        const tokenSecret = this.tokenConfig[type].secret;

        if (!tokenSecret) throw new Error(`${type} token secret undefined.`);

        const { payload } = await Jose.jwtVerify<TPayload>(
            token,
            NextJoseAuthClient.secretEncoder.encode(tokenSecret)
        );

        return payload;
    }

    public async refreshAccessToken(
        request: NextRequest,
        response: NextResponse
    ) {
        const checkRoute = (route: string): boolean =>
            request.nextUrl.pathname.startsWith(route);

        const isProtectedRoute = this.protectedRoutes.some(checkRoute);
        const isPublicRoute = this.publicRoutes.some(checkRoute);

        const [atError] = await catchErrors(
            this.verifyToken(
                'access',
                request.cookies.get(this.tokenConfig.access.cookieName)?.value
            )
        );

        if (!atError) {
            if (isPublicRoute)
                return NextResponse.redirect(
                    new URL(this.redirects.auth, request.url)
                );

            return response;
        }

        const [rtError, payload] = await catchErrors(
            this.verifyToken(
                'refresh',
                request.cookies.get(this.tokenConfig.refresh.cookieName)?.value
            )
        );

        if (rtError) {
            if (isProtectedRoute)
                return NextResponse.redirect(
                    new URL(this.redirects.noAuth, request.url)
                );

            return response;
        }

        const newAccessTokenCookieConfig = await this.signToken(
            'access',
            payload
        );

        response.cookies.set(newAccessTokenCookieConfig);

        return response;
    }

    public async getSession<T>(selector?: (payload: TPayload) => T) {
        const cookieStore = await cookies();

        const sel = (selector ?? ((payload) => payload)) as (
            payload: TPayload
        ) => T;

        const [error, payload] = await catchErrors(
            this.verifyToken(
                'access',
                cookieStore.get(this.tokenConfig.access.cookieName)?.value
            )
        );

        if (error) {
            if (!__PROD__) console.log(error.message);

            return null;
        }

        return sel(payload);
    }
}

export default NextJoseAuthClient;
