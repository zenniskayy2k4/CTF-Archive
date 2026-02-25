namespace System.Drawing.Imaging
{
	/// <summary>Used to specify the parameter value passed to a JPEG or TIFF image encoder when using the <see cref="M:System.Drawing.Image.Save(System.String,System.Drawing.Imaging.ImageCodecInfo,System.Drawing.Imaging.EncoderParameters)" /> or <see cref="M:System.Drawing.Image.SaveAdd(System.Drawing.Imaging.EncoderParameters)" /> methods.</summary>
	public enum EncoderValue
	{
		/// <summary>Not used in GDI+ version 1.0.</summary>
		ColorTypeCMYK = 0,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		ColorTypeYCCK = 1,
		/// <summary>Specifies the LZW compression scheme. Can be passed to the TIFF encoder as a parameter that belongs to the Compression category.</summary>
		CompressionLZW = 2,
		/// <summary>Specifies the CCITT3 compression scheme. Can be passed to the TIFF encoder as a parameter that belongs to the compression category.</summary>
		CompressionCCITT3 = 3,
		/// <summary>Specifies the CCITT4 compression scheme. Can be passed to the TIFF encoder as a parameter that belongs to the compression category.</summary>
		CompressionCCITT4 = 4,
		/// <summary>Specifies the RLE compression scheme. Can be passed to the TIFF encoder as a parameter that belongs to the compression category.</summary>
		CompressionRle = 5,
		/// <summary>Specifies no compression. Can be passed to the TIFF encoder as a parameter that belongs to the compression category.</summary>
		CompressionNone = 6,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		ScanMethodInterlaced = 7,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		ScanMethodNonInterlaced = 8,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		VersionGif87 = 9,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		VersionGif89 = 10,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		RenderProgressive = 11,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		RenderNonProgressive = 12,
		/// <summary>Specifies that the image is to be rotated clockwise 90 degrees about its center. Can be passed to the JPEG encoder as a parameter that belongs to the transformation category.</summary>
		TransformRotate90 = 13,
		/// <summary>Specifies that the image is to be rotated 180 degrees about its center. Can be passed to the JPEG encoder as a parameter that belongs to the transformation category.</summary>
		TransformRotate180 = 14,
		/// <summary>Specifies that the image is to be rotated clockwise 270 degrees about its center. Can be passed to the JPEG encoder as a parameter that belongs to the transformation category.</summary>
		TransformRotate270 = 15,
		/// <summary>Specifies that the image is to be flipped horizontally (about the vertical axis). Can be passed to the JPEG encoder as a parameter that belongs to the transformation category.</summary>
		TransformFlipHorizontal = 16,
		/// <summary>Specifies that the image is to be flipped vertically (about the horizontal axis). Can be passed to the JPEG encoder as a parameter that belongs to the transformation category.</summary>
		TransformFlipVertical = 17,
		/// <summary>Specifies that the image has more than one frame (page). Can be passed to the TIFF encoder as a parameter that belongs to the save flag category.</summary>
		MultiFrame = 18,
		/// <summary>Specifies the last frame in a multiple-frame image. Can be passed to the TIFF encoder as a parameter that belongs to the save flag category.</summary>
		LastFrame = 19,
		/// <summary>Specifies that a multiple-frame file or stream should be closed. Can be passed to the TIFF encoder as a parameter that belongs to the save flag category.</summary>
		Flush = 20,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		FrameDimensionTime = 21,
		/// <summary>Not used in GDI+ version 1.0.</summary>
		FrameDimensionResolution = 22,
		/// <summary>Specifies that a frame is to be added to the page dimension of an image. Can be passed to the TIFF encoder as a parameter that belongs to the save flag category.</summary>
		FrameDimensionPage = 23
	}
}
