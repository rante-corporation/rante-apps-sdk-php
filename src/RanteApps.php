<?php

declare(strict_types=1);

namespace Rante\Apps;

/** Constants of the Rante Apps server SDK. */
final class RanteApps
{
    public const VERSION = '0.1.0';

    /** Rante Login, which issues app access tokens. */
    public const DEFAULT_AUTHORITY = 'https://login.rante.com';

    /** The Content-Security-Policy directive an external app's pages send so that only Rante can frame them. */
    public const FRAME_ANCESTORS = 'frame-ancestors https://portal.rante.com';
}
