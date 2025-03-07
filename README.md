# next-ims-lti-ssl

## Installation

```bash
npm i next-ims-lti-ssl
```

## Example

```jsx
import getLtiContext from 'next-ims-lti-ssl';

const App = ({ context }) => {
  return (
    <pre>
      <code>{JSON.stringify(context, null, 2)}</code>
    </pre>
  );
};

export const getServerSideProps = async (ctx) => {
  const ltiContext = await getLtiContext({
    ctx,
    key: 'consumer-key',
    secret: 'consumer-secret',
    persist: false,
    cookieOptions:{
      path: '/',
    }
  });
  return {
    props: {
      context: ltiContext,
    },
  };
};

export default App;
```
