import { describe, expect, it } from "vite-plus/test";
import { runScanRule } from "../../../test-utils/run-scan-rule.js";
import { unsafeJsonInHtml } from "./unsafe-json-in-html.js";

const scan = (content: string, relativePath = "src/component.tsx") =>
  runScanRule(unsafeJsonInHtml, { relativePath, content });

describe("security-scan/unsafe-json-in-html — regressions", () => {
  it("stays silent when JSON.stringify is the injected script's own runtime code", () => {
    const content = `const html = \`
  <body>
    <script type="text/javascript">
      const handleSessionUpdate = (event) => {
        window.ReactNativeWebView.postMessage(JSON.stringify(event.payload.session))
      }
    </script>
  </body>
\`;
`;
    expect(scan(content)).toHaveLength(0);
  });

  it("stays silent on a React-escaped JSX text child of <script>", () => {
    const content = `export function Register({ ids }: { ids: string[] }) {
  return (
    <script>{\`window.__TableOfContents__?.register(\${JSON.stringify(ids)});\`}</script>
  );
}
`;
    expect(scan(content)).toHaveLength(0);
  });

  it("stays silent on a fully hardcoded JSON-LD literal", () => {
    const content = `export const Head = () => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify({
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": "Rad UI",
        "operatingSystem": "Web",
        "aggregateRating": { "@type": "AggregateRating", "ratingValue": "5", "ratingCount": 4 },
        "isAccessibleForFree": true,
      })
    }}
  />
);
`;
    expect(scan(content)).toHaveLength(0);
  });

  it("still flags stringified dynamic data interpolated into a script template", () => {
    const content = `export const buildHtml = (data: unknown) => \`
  <script>window.__DATA__ = \${JSON.stringify(data)};</script>
\`;
`;
    expect(scan(content)).toBeTruthy();
    expect(scan(content).length).toBeGreaterThan(0);
  });

  it("still flags stringified dynamic data joined by string concat", () => {
    const content = `export const buildHtml = (data: unknown) =>
  "<script>window.__DATA__ = " + JSON.stringify(data) + ";</script>";
`;
    expect(scan(content).length).toBeGreaterThan(0);
  });

  it("still flags unescaped JSON-LD built from a dynamic value", () => {
    const content = `export const Seo = ({ structuredData }: { structuredData: object }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
  />
);
`;
    expect(scan(content, "src/seo.tsx").length).toBeGreaterThan(0);
  });

  it("stays silent when JSON-LD escapes less-than signs with replaceAll", () => {
    const content = `export const Seo = ({ jsonLd }: { jsonLd: object }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify(jsonLd).replaceAll("<", "\\\\u003c")
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx")).toHaveLength(0);
  });

  it("stays silent when JSON-LD escapes less-than signs with replace", () => {
    const content = `export const Seo = ({ jsonLd }: { jsonLd: object }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify(jsonLd).replace(/</g, "\\\\u003c")
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx")).toHaveLength(0);
  });

  it("still flags replaceAll when it does not escape less-than signs", () => {
    const content = `export const Seo = ({ jsonLd }: { jsonLd: object }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify(jsonLd).replaceAll(">", "\\\\u003e")
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx").length).toBeGreaterThan(0);
  });

  it("still flags replaceAll when its search value is not a less-than sign", () => {
    const content = `export const Seo = ({ jsonLd }: { jsonLd: object }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify(jsonLd).replaceAll(">", "\\\\u003c")
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx").length).toBeGreaterThan(0);
  });

  it("still flags replaceAll when its replacement contains a raw less-than sign", () => {
    const content = `export const Seo = ({ jsonLd }: { jsonLd: object }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify(jsonLd).replaceAll("<", "<")
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx").length).toBeGreaterThan(0);
  });

  it("still flags when only one JSON.stringify input value is escaped", () => {
    const content = `export const Seo = ({ jsonLd }: { jsonLd: string }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify({
        raw: jsonLd,
        escaped: jsonLd.replaceAll("<", "\\\\u003c")
      })
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx").length).toBeGreaterThan(0);
  });

  it("still flags a similarly named return-value method", () => {
    const content = `export const Seo = ({ jsonLd }: { jsonLd: object }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify(jsonLd).replaceAllHtml("<", "\\\\u003c")
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx").length).toBeGreaterThan(0);
  });

  it("still flags a literal argument that mixes in identifiers", () => {
    const content = `export const Seo = ({ title }: { title: string }) => (
  <script
    type="application/ld+json"
    dangerouslySetInnerHTML={{
      __html: JSON.stringify({ "@type": "Article", "headline": title })
    }}
  />
);
`;
    expect(scan(content, "src/seo.tsx").length).toBeGreaterThan(0);
  });
});
