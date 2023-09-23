import lti from 'ims-lti';
import bodyParser from 'body-parser';
import { useCookie as getCookie } from 'next-cookie';
import { GetServerSidePropsContext } from 'next';

import { IncomingMessage, ServerResponse } from 'http';

const setMiddleware = (
  req: IncomingMessage,
  res: ServerResponse
): Promise<{ req: IncomingMessage; res: ServerResponse }> => {
  return new Promise((resolve) => {
    bodyParser.urlencoded({ extended: true })(req, res, () => {
      bodyParser.json()(req, res, () => {
        resolve({ req, res });
      });
    });
  });
};

const toBase64 = (str: string): string => {
  let _str;
  try {
    _str = Buffer.from(Buffer.from(str).toString('base64')).toString('base64');
    return _str;
  } catch (e) {
    return toBase64(JSON.stringify({ error: e }));
  }
};

const toNormalString = (str: string): string => {
  let _str;
  try {
    _str = Buffer.from(
      Buffer.from(str, 'base64').toString(),
      'base64'
    ).toString();
    return _str;
  } catch (e) {
    return JSON.stringify({ error: e });
  }
};

interface VerifyLti {
  ctx: GetServerSidePropsContext;
  request: any;
  key: string;
  secret: string;
  persist: boolean;
  cookieOptions?: any;
}

const verifyLti = ({
  ctx,
  request,
  key,
  secret,
  persist,
  cookieOptions,
}: VerifyLti) => {
  return new Promise((resolve) => {
    const moodleData = new lti.Provider(key, secret);

    moodleData.valid_request(request, (err: Error, isValid: boolean) => {
      const cookie = getCookie(ctx);
      if (!isValid) {
        if (persist) {
          const myb = toBase64(JSON.stringify({ error: err }));
          cookie.set('HEp8hAsCelpLI3EX', myb, {
            maxAge: 1000 * 60 * 60 * 24 * 365,
            path: '/',
            ...cookieOptions,
          });
        }

        // console.error(`not valid: ${err}`);
        resolve({ error: err });
      } else {
        if (persist) {
          const myb = toBase64(JSON.stringify(moodleData.body));
          cookie.set('HEp8hAsCelpLI3EX', myb, {
            maxAge: 1000 * 60 * 60 * 24 * 365,
            path: '/',
            ...cookieOptions,
          });
        }
        resolve(moodleData.body);
        // console.log('valid');
      }
    });
  });
};

interface GetLtiContext {
  ctx: GetServerSidePropsContext;
  key: string;
  secret: string;
  persist: boolean;
  cookieOptions?: any;
}

const getLtiContext = async ({
  ctx,
  key,
  secret,
  persist,
  cookieOptions = {},
}: GetLtiContext) => {
  const { req, res } = ctx;

  if (req.method === 'POST') {
    const { req: request } = await setMiddleware(req, res);
    const lticontext = await verifyLti({
      ctx,
      request,
      key,
      secret,
      persist,
      cookieOptions,
    });
    return lticontext;
  }

  if (persist) {
    const cookie = getCookie(ctx);
    try {
      const ltiContext = JSON.parse(
        toNormalString(cookie.get('HEp8hAsCelpLI3EX'))
      );

      return ltiContext || {};
    } catch (e) {
      return { error: e };
    }
  }

  const cookie = getCookie(ctx);
  const myb = toBase64(JSON.stringify({}));
  cookie.set('HEp8hAsCelpLI3EX', myb, {
    maxAge: 0,
    path: '/',
    ...cookieOptions,
  });

  return {};
};

export default getLtiContext;
