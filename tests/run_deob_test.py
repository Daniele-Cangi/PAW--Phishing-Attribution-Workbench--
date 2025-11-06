# Small harness to validate URL deobfuscation behaviors
from paw.deobfuscate.url import URLDeobfuscator

cases = [
    # multi-layer sample (hxxps + [.] + homoglyph + base64 token)
    (
        "hxxps://google[.]com-verify.рayраl.соm/secure-login?token=aHR0cHM6Ly9yZWFsLXBoaXNoLmNvbQ==",
        "https://google.com-verify.paypal.com/secure-login?token=https://real-phish.com"
    ),
    # simple bracket-dot and percent-encoding
    (
        "hxxp://example[.]com/%70%61%79%6c%6f%61%64",
        "http://example.com/payload"
    ),
    # urlsafe base64 unpadded token
    (
        "https://legit.com/?q=aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXlsb2Fk",
        "https://legit.com/?q=https://example.com/payload"
    )
]

if __name__ == '__main__':
    d = URLDeobfuscator()
    for inp, expected in cases:
        out = d.deobfuscate_url(inp)
        print('INPUT :', inp)
        print('OUTPUT:', out.get('final_url'))
        print('TRANS :', [t['technique'] for t in out.get('transformations', [])])
        print('SCORE :', out.get('suspicion_score'))
        print('-'*60)
        # simple assertion (best effort, not raising in harness)
        if expected in out.get('final_url', ''):
            print('-> OK\n')
        else:
            print('-> MISMATCH (expected part):', expected, '\n')
