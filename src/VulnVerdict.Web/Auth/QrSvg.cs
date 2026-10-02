using QRCoder;

namespace VulnVerdict.Web;

/// <summary>
/// The enrolment QR code as inline SVG, drawn on the server. The secret never goes to an image service and no
/// script is involved, which the content security policy would refuse anyway.
/// </summary>
public static class QrSvg
{
    public static string Render(string text)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        return new SvgQRCode(data).GetGraphic(4, "#000000", "#ffffff", drawQuietZones: true, SvgQRCode.SizingMode.ViewBoxAttribute);
    }
}
