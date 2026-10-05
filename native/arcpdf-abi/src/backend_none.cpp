// SPDX-License-Identifier: AGPL-3.0-only
#include "pdf_backend.hpp"

// No PDF parser is linked into this build. arc_pdf_open then fails closed with ARC_UNSUPPORTED; the library never
// substitutes a fallback parser. The PDFium binding replaces this translation unit and is not part of this delivery.
std::shared_ptr<arc::pdf::backend> arc::pdf::linked_backend()
{
    return nullptr;
}
