// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.DesignSystem;

public enum ThemeMode
{
    Light,
    Dark,
    HighContrast
}

public enum DensityMode
{
    Comfortable,
    Compact,
    ProfessionalDense
}

public enum TypographyRole
{
    Display,
    PageTitle,
    SectionTitle,
    Body,
    EmphasizedBody,
    Caption,
    TabularNumber
}

public enum FontWeight
{
    Regular,
    Medium,
    SemiBold,
    Bold
}

public enum FontFamilyToken
{
    Interface,
    Numeric
}

public enum MotionCurve
{
    Standard,
    Emphasized
}

public enum MotionDuration
{
    Fast,
    Standard,
    Emphasized
}

public enum MotionPreference
{
    Standard,
    Reduced
}

public readonly record struct RgbaColor(byte Red, byte Green, byte Blue, byte Alpha = byte.MaxValue);

public readonly record struct SemanticPalette(
    RgbaColor Canvas,
    RgbaColor Surface,
    RgbaColor ElevatedSurface,
    RgbaColor TextPrimary,
    RgbaColor TextSecondary,
    RgbaColor TextDisabled,
    RgbaColor Accent,
    RgbaColor OnAccent,
    RgbaColor Danger,
    RgbaColor OnDanger,
    RgbaColor Warning,
    RgbaColor OnWarning,
    RgbaColor Success,
    RgbaColor OnSuccess,
    RgbaColor Informational,
    RgbaColor OnInformational,
    RgbaColor FocusRing);

public readonly record struct TextStyleToken(
    double FontSize,
    double LineHeight,
    FontWeight Weight,
    FontFamilyToken Family,
    bool UsesTabularFigures);

public readonly record struct TypographyTokens(
    TextStyleToken Display,
    TextStyleToken PageTitle,
    TextStyleToken SectionTitle,
    TextStyleToken Body,
    TextStyleToken EmphasizedBody,
    TextStyleToken Caption,
    TextStyleToken TabularNumber)
{
    public TextStyleToken For(TypographyRole role)
        => role switch
        {
            TypographyRole.Display => Display,
            TypographyRole.PageTitle => PageTitle,
            TypographyRole.SectionTitle => SectionTitle,
            TypographyRole.Body => Body,
            TypographyRole.EmphasizedBody => EmphasizedBody,
            TypographyRole.Caption => Caption,
            TypographyRole.TabularNumber => TabularNumber,
            _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown typography role."),
        };
}

public readonly record struct SpacingTokens(
    double None,
    double Hairline,
    double Micro,
    double Tight,
    double Compact,
    double Regular,
    double Relaxed,
    double Section,
    double Roomy);

public readonly record struct ShapeTokens(
    double None,
    double Subtle,
    double Control,
    double Panel,
    double Dialog,
    double Pill);

public readonly record struct ShadowToken(double OffsetY, double BlurRadius, double SpreadRadius, RgbaColor Color);

public readonly record struct ElevationTokens(ShadowToken None, ShadowToken Raised, ShadowToken Overlay);

public readonly record struct MotionTokens(
    TimeSpan Fast,
    TimeSpan Standard,
    TimeSpan Emphasized,
    MotionCurve StandardCurve,
    MotionCurve EmphasizedCurve)
{
    public TimeSpan Resolve(MotionDuration duration, MotionPreference preference)
    {
        var durationValue = duration switch
        {
            MotionDuration.Fast => Fast,
            MotionDuration.Standard => Standard,
            MotionDuration.Emphasized => Emphasized,
            _ => throw new ArgumentOutOfRangeException(nameof(duration), duration, "Unknown motion duration."),
        };

        return preference switch
        {
            MotionPreference.Standard => durationValue,
            MotionPreference.Reduced => TimeSpan.Zero,
            _ => throw new ArgumentOutOfRangeException(nameof(preference), preference, "Unknown motion preference."),
        };
    }

    public MotionCurve CurveFor(MotionDuration duration)
        => duration switch
        {
            MotionDuration.Fast or MotionDuration.Standard => StandardCurve,
            MotionDuration.Emphasized => EmphasizedCurve,
            _ => throw new ArgumentOutOfRangeException(nameof(duration), duration, "Unknown motion duration."),
        };
}

public readonly record struct DensityTokens(
    double ControlHeight,
    double RowHeight,
    double PanelPadding,
    double SectionGap,
    double InlineGap);

public readonly record struct DesignTokenSet(
    ThemeMode Theme,
    DensityMode Density,
    SemanticPalette Colors,
    TypographyTokens Typography,
    SpacingTokens Spacing,
    ShapeTokens Shape,
    ElevationTokens Elevation,
    MotionTokens Motion,
    DensityTokens Measurements);

public static class DesignTokens
{
    private static readonly SemanticPalette LightPalette = new(
        Canvas: new(255, 255, 255),
        Surface: new(246, 248, 251),
        ElevatedSurface: new(255, 255, 255),
        TextPrimary: new(25, 31, 40),
        TextSecondary: new(61, 70, 82),
        TextDisabled: new(92, 100, 111),
        Accent: new(23, 72, 145),
        OnAccent: new(255, 255, 255),
        Danger: new(139, 29, 24),
        OnDanger: new(255, 255, 255),
        Warning: new(104, 71, 0),
        OnWarning: new(255, 255, 255),
        Success: new(20, 91, 49),
        OnSuccess: new(255, 255, 255),
        Informational: new(12, 83, 119),
        OnInformational: new(255, 255, 255),
        FocusRing: new(0, 61, 157));

    private static readonly SemanticPalette DarkPalette = new(
        Canvas: new(17, 19, 24),
        Surface: new(28, 32, 39),
        ElevatedSurface: new(39, 45, 54),
        TextPrimary: new(245, 246, 248),
        TextSecondary: new(199, 205, 214),
        TextDisabled: new(166, 174, 185),
        Accent: new(151, 190, 249),
        OnAccent: new(10, 28, 52),
        Danger: new(255, 180, 170),
        OnDanger: new(54, 0, 3),
        Warning: new(255, 216, 111),
        OnWarning: new(52, 37, 0),
        Success: new(145, 226, 164),
        OnSuccess: new(0, 47, 22),
        Informational: new(151, 210, 247),
        OnInformational: new(0, 39, 60),
        FocusRing: new(173, 202, 255));

    private static readonly SemanticPalette HighContrastPalette = new(
        Canvas: new(0, 0, 0),
        Surface: new(0, 0, 0),
        ElevatedSurface: new(0, 0, 0),
        TextPrimary: new(255, 255, 255),
        TextSecondary: new(255, 255, 255),
        TextDisabled: new(211, 211, 211),
        Accent: new(255, 255, 0),
        OnAccent: new(0, 0, 0),
        Danger: new(255, 77, 77),
        OnDanger: new(0, 0, 0),
        Warning: new(255, 255, 0),
        OnWarning: new(0, 0, 0),
        Success: new(0, 255, 0),
        OnSuccess: new(0, 0, 0),
        Informational: new(0, 255, 255),
        OnInformational: new(0, 0, 0),
        FocusRing: new(255, 255, 255));

    private static readonly TypographyTokens TypeScale = new(
        Display: new(32, 40, FontWeight.Bold, FontFamilyToken.Interface, false),
        PageTitle: new(24, 32, FontWeight.SemiBold, FontFamilyToken.Interface, false),
        SectionTitle: new(20, 28, FontWeight.SemiBold, FontFamilyToken.Interface, false),
        Body: new(16, 24, FontWeight.Regular, FontFamilyToken.Interface, false),
        EmphasizedBody: new(16, 24, FontWeight.SemiBold, FontFamilyToken.Interface, false),
        Caption: new(12, 16, FontWeight.Medium, FontFamilyToken.Interface, false),
        TabularNumber: new(14, 20, FontWeight.Regular, FontFamilyToken.Numeric, true));

    private static readonly SpacingTokens SpacingScale = new(
        None: 0,
        Hairline: 1,
        Micro: 2,
        Tight: 4,
        Compact: 8,
        Regular: 12,
        Relaxed: 16,
        Section: 24,
        Roomy: 32);

    private static readonly ShapeTokens ShapeScale = new(
        None: 0,
        Subtle: 2,
        Control: 4,
        Panel: 8,
        Dialog: 12,
        Pill: 999);

    private static readonly ElevationTokens ElevationScale = new(
        None: new(0, 0, 0, new(0, 0, 0, 0)),
        Raised: new(1, 4, 0, new(0, 0, 0, 28)),
        Overlay: new(4, 16, 0, new(0, 0, 0, 48)));

    private static readonly MotionTokens MotionScale = new(
        Fast: TimeSpan.FromMilliseconds(100),
        Standard: TimeSpan.FromMilliseconds(180),
        Emphasized: TimeSpan.FromMilliseconds(260),
        StandardCurve: MotionCurve.Standard,
        EmphasizedCurve: MotionCurve.Emphasized);

    public static DesignTokenSet Get(ThemeMode theme, DensityMode density)
    {
        var palette = theme switch
        {
            ThemeMode.Light => LightPalette,
            ThemeMode.Dark => DarkPalette,
            ThemeMode.HighContrast => HighContrastPalette,
            _ => throw new ArgumentOutOfRangeException(nameof(theme), theme, "Unknown theme mode."),
        };

        var measurements = density switch
        {
            DensityMode.Comfortable => new DensityTokens(36, 40, 24, 24, 12),
            DensityMode.Compact => new DensityTokens(30, 32, 16, 16, 8),
            DensityMode.ProfessionalDense => new DensityTokens(24, 28, 12, 12, 6),
            _ => throw new ArgumentOutOfRangeException(nameof(density), density, "Unknown density mode."),
        };

        return new DesignTokenSet(
            theme,
            density,
            palette,
            TypeScale,
            SpacingScale,
            ShapeScale,
            ElevationScale,
            MotionScale,
            measurements);
    }
}

public static class ColorContrast
{
    public static double Ratio(RgbaColor first, RgbaColor second)
    {
        if (first.Alpha != byte.MaxValue || second.Alpha != byte.MaxValue)
        {
            throw new ArgumentException("Contrast ratios require fully opaque colors.");
        }

        var firstLuminance = RelativeLuminance(first);
        var secondLuminance = RelativeLuminance(second);
        var lighter = Math.Max(firstLuminance, secondLuminance);
        var darker = Math.Min(firstLuminance, secondLuminance);
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double RelativeLuminance(RgbaColor color)
        => (0.2126 * Linearize(color.Red / 255d))
            + (0.7152 * Linearize(color.Green / 255d))
            + (0.0722 * Linearize(color.Blue / 255d));

    private static double Linearize(double component)
        => component <= 0.04045
            ? component / 12.92
            : Math.Pow((component + 0.055) / 1.055, 2.4);
}
