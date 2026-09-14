pkgname=omarchyair-helper
pkgver=0.3.1
pkgrel=1
pkgdesc='Signed, narrowly-scoped privileged network helper for Omarchy Air'
url='https://github.com/SantanaJcp/omarchyair'
arch=('any')
license=('MIT')
depends=('python' 'pipewire-zeroconf' 'avahi' 'ufw')
source=('omarchyair_helper.py' 'omarchyair_runtime.py' 'omarchyair-helper' 'LICENSE')
sha256sums=('d87bdc85ac44fd3039f866e47ebf7cc9f1ffae8f1c96ed7ba87c0c37af6764ee'
            '158e0fa74c31720561d4037c805c82aa558bb55b9c47637b82e49303e77a4313'
            '99ad14199265df254017f44c90843873d79d830a2bcec857d6ab4dc7e585241a'
            '428ffd68b3e195693d64aa8c204063d0f42acc65a0dcbcae07aa3ae95afe19f4')

package() {
    install -Dm755 "$srcdir/omarchyair-helper" \
        "$pkgdir/usr/bin/omarchyair-helper"
    install -Dm644 "$srcdir/omarchyair_helper.py" \
        "$pkgdir/usr/lib/omarchyair/omarchyair_helper.py"
    install -Dm644 "$srcdir/omarchyair_runtime.py" \
        "$pkgdir/usr/lib/omarchyair/omarchyair_runtime.py"
    install -Dm644 "$srcdir/LICENSE" \
        "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
