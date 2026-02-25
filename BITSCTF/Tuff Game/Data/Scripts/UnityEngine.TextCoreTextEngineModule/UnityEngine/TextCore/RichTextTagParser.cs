#define UNITY_ASSERTIONS
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using UnityEngine.Bindings;
using UnityEngine.TextCore.Text;

namespace UnityEngine.TextCore
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal static class RichTextTagParser
	{
		public enum TagType
		{
			Hyperlink = 0,
			Align = 1,
			AllCaps = 2,
			Alpha = 3,
			Bold = 4,
			Br = 5,
			Color = 6,
			CSpace = 7,
			Font = 8,
			FontWeight = 9,
			Italic = 10,
			Indent = 11,
			LineHeight = 12,
			LineIndent = 13,
			Link = 14,
			Lowercase = 15,
			Margin = 16,
			MarginLeft = 17,
			MarginRight = 18,
			Mark = 19,
			Mspace = 20,
			NoBr = 21,
			NoParse = 22,
			Strikethrough = 23,
			Size = 24,
			SmallCaps = 25,
			Space = 26,
			Sprite = 27,
			Style = 28,
			Subscript = 29,
			Superscript = 30,
			Underline = 31,
			Uppercase = 32,
			Unknown = 33
		}

		public enum ValueID
		{
			Color = 0,
			Padding = 1,
			AssetID = 2,
			GlyphMetrics = 3,
			Scale = 4,
			Tint = 5,
			SpriteColor = 6
		}

		internal record TagTypeInfo
		{
			public TagType TagType;

			public string name;

			public TagValueType valueType;

			public TagUnitType unitType;

			internal TagTypeInfo(TagType tagType, string name, TagValueType valueType = TagValueType.None, TagUnitType unitType = TagUnitType.Unknown)
			{
				TagType = tagType;
				this.name = name;
				this.valueType = valueType;
				this.unitType = unitType;
			}
		}

		internal enum TagValueType
		{
			None = 0,
			NumericalValue = 1,
			StringValue = 2,
			ColorValue = 3,
			Vector4Value = 4,
			GlyphMetricsValue = 5,
			BoolValue = 6
		}

		internal enum TagUnitType
		{
			Unknown = 0,
			Pixels = 1,
			FontUnits = 2,
			Percentage = 3
		}

		internal record TagValue
		{
			internal string? StringValue
			{
				get
				{
					if (type != TagValueType.StringValue)
					{
						throw new InvalidOperationException("Not a string value");
					}
					return m_stringValue;
				}
			}

			internal float NumericalValue
			{
				get
				{
					if (type != TagValueType.NumericalValue)
					{
						throw new InvalidOperationException("Not a numerical value");
					}
					return m_numericalValue;
				}
			}

			internal Color ColorValue
			{
				get
				{
					if (type != TagValueType.ColorValue)
					{
						throw new InvalidOperationException("Not a color value");
					}
					return m_colorValue;
				}
			}

			internal Vector4 Vector4Value
			{
				get
				{
					if (type != TagValueType.Vector4Value)
					{
						throw new InvalidOperationException("Not a vector4 value");
					}
					return m_vector4Value;
				}
			}

			internal GlyphMetrics GlyphMetricsValue
			{
				get
				{
					if (type != TagValueType.GlyphMetricsValue)
					{
						throw new InvalidOperationException("Not a GlyphMetrics value");
					}
					return m_glyphMetricsValue;
				}
			}

			internal bool BoolValue
			{
				get
				{
					if (type != TagValueType.BoolValue)
					{
						throw new InvalidOperationException("Not a Bool value");
					}
					return m_boolValue;
				}
			}

			internal ValueID? ID => m_ID;

			internal TagValueType type;

			internal TagUnitType unit;

			private string? m_stringValue;

			private float m_numericalValue;

			private Color m_colorValue;

			private Vector4 m_vector4Value;

			private GlyphMetrics m_glyphMetricsValue;

			private bool m_boolValue;

			private ValueID? m_ID;

			internal TagValue(float value, TagUnitType tagUnitType = TagUnitType.Unknown, ValueID? id = null)
			{
				type = TagValueType.NumericalValue;
				unit = tagUnitType;
				m_numericalValue = value;
				m_ID = id;
			}

			internal TagValue(Color value, ValueID? id = null)
			{
				type = TagValueType.ColorValue;
				m_colorValue = value;
				m_ID = id;
			}

			internal TagValue(string value, ValueID? id = null)
			{
				type = TagValueType.StringValue;
				m_stringValue = value;
				m_ID = id;
			}

			internal TagValue(Vector4 value, ValueID? id = null)
			{
				type = TagValueType.Vector4Value;
				m_vector4Value = value;
				m_ID = id;
			}

			internal TagValue(GlyphMetrics value, ValueID? id = null)
			{
				type = TagValueType.GlyphMetricsValue;
				m_glyphMetricsValue = value;
				m_ID = id;
			}

			internal TagValue(bool value, ValueID? id = null)
			{
				type = TagValueType.BoolValue;
				m_boolValue = value;
				m_ID = id;
			}
		}

		internal struct Tag
		{
			public TagType tagType;

			public bool isClosing;

			public int start;

			public int end;

			public TagValue? value;

			public TagValue? value2;

			public TagValue? value3;

			public TagValue? value4;

			public TagValue? value5;
		}

		public struct Segment
		{
			public List<Tag>? tags;

			public int start;

			public int end;
		}

		internal record ParseError
		{
			public readonly int position;

			public readonly string message;

			internal ParseError(string message, int position)
			{
				this.message = message;
				this.position = position;
			}
		}

		internal static readonly Color32 k_HighlightColor = new Color32(byte.MaxValue, byte.MaxValue, 0, 64);

		internal static readonly char k_PrivateArea = '\ue000';

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
		internal static readonly Dictionary<string, IntPtr> s_FontAssetCache = new Dictionary<string, IntPtr>();

		internal static readonly Dictionary<string, WeakReference<SpriteAsset>> s_SpriteAssetCache = new Dictionary<string, WeakReference<SpriteAsset>>();

		internal static readonly TagTypeInfo[] TagsInfo = new TagTypeInfo[33]
		{
			new TagTypeInfo(TagType.Hyperlink, "a"),
			new TagTypeInfo(TagType.Align, "align"),
			new TagTypeInfo(TagType.AllCaps, "allcaps"),
			new TagTypeInfo(TagType.Alpha, "alpha"),
			new TagTypeInfo(TagType.Bold, "b"),
			new TagTypeInfo(TagType.Br, "br"),
			new TagTypeInfo(TagType.Color, "color", TagValueType.ColorValue),
			new TagTypeInfo(TagType.CSpace, "cspace"),
			new TagTypeInfo(TagType.Font, "font"),
			new TagTypeInfo(TagType.FontWeight, "font-weight"),
			new TagTypeInfo(TagType.Italic, "i"),
			new TagTypeInfo(TagType.Indent, "indent"),
			new TagTypeInfo(TagType.LineHeight, "line-height"),
			new TagTypeInfo(TagType.LineIndent, "line-indent"),
			new TagTypeInfo(TagType.Link, "link"),
			new TagTypeInfo(TagType.Lowercase, "lowercase"),
			new TagTypeInfo(TagType.Margin, "margin"),
			new TagTypeInfo(TagType.MarginLeft, "margin-left"),
			new TagTypeInfo(TagType.MarginRight, "margin-right"),
			new TagTypeInfo(TagType.Mark, "mark"),
			new TagTypeInfo(TagType.Mspace, "mspace"),
			new TagTypeInfo(TagType.NoBr, "nobr"),
			new TagTypeInfo(TagType.NoParse, "noparse"),
			new TagTypeInfo(TagType.Strikethrough, "s"),
			new TagTypeInfo(TagType.Size, "size"),
			new TagTypeInfo(TagType.SmallCaps, "smallcaps"),
			new TagTypeInfo(TagType.Space, "space"),
			new TagTypeInfo(TagType.Sprite, "sprite"),
			new TagTypeInfo(TagType.Style, "style"),
			new TagTypeInfo(TagType.Subscript, "sub"),
			new TagTypeInfo(TagType.Superscript, "sup"),
			new TagTypeInfo(TagType.Underline, "u"),
			new TagTypeInfo(TagType.Uppercase, "uppercase")
		};

		private const string k_FontTag = "<font=";

		private const string k_SpriteTag = "<sprite";

		private const string k_StyleTag = "<style=\"";

		private static bool tagMatch(ReadOnlySpan<char> tagCandidate, string tagName)
		{
			return tagCandidate.StartsWith(tagName.AsSpan()) && (tagCandidate.Length == tagName.Length || (!char.IsLetter(tagCandidate[tagName.Length]) && tagCandidate[tagName.Length] != '-'));
		}

		private static bool SpanToEnum(ReadOnlySpan<char> tagCandidate, out TagType tagType, out string? error, out ReadOnlySpan<char> attribute)
		{
			for (int i = 0; i < TagsInfo.Length; i++)
			{
				string name = TagsInfo[i].name;
				if (tagMatch(tagCandidate, name))
				{
					tagType = TagsInfo[i].TagType;
					error = null;
					attribute = tagCandidate.Slice(name.Length);
					return true;
				}
			}
			if (tagCandidate.Length > 4 && tagCandidate[0] == '#')
			{
				tagType = TagType.Color;
				error = null;
				attribute = tagCandidate;
				return true;
			}
			error = "Unknown tag: " + tagCandidate;
			tagType = TagType.Unknown;
			attribute = null;
			return false;
		}

		private static TagValue? ParseColorAttribute(ReadOnlySpan<char> attributeSection)
		{
			attributeSection = GetAttributeSpan(attributeSection);
			if (ColorUtility.TryParseHtmlString(attributeSection, out var color))
			{
				return new TagValue(color, ValueID.Color);
			}
			return null;
		}

		private static TagValue? ParsePaddingAttribute(ReadOnlySpan<char> value)
		{
			Span<int> span = stackalloc int[4];
			int num = 0;
			while (!value.IsEmpty && num < 4)
			{
				int num2 = value.IndexOf(',');
				ReadOnlySpan<char> s;
				if (num2 >= 0)
				{
					s = value.Slice(0, num2);
					value = value.Slice(num2 + 1);
				}
				else
				{
					s = value;
					value = ReadOnlySpan<char>.Empty;
				}
				if (!int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out span[num]))
				{
					return null;
				}
				num++;
			}
			if (num != 4)
			{
				return null;
			}
			return new TagValue(new Vector4(span[0], span[1], span[2], span[3]), ValueID.Padding);
		}

		private static TagValue? ParseHref(ReadOnlySpan<char> attributeSection)
		{
			if (TryGetSimpleHref(attributeSection, out string hrefValue))
			{
				return new TagValue(hrefValue);
			}
			return new TagValue(attributeSection.TrimStart().ToString());
		}

		private static bool TryGetSimpleHref(ReadOnlySpan<char> attributeSection, out string hrefValue)
		{
			hrefValue = "";
			attributeSection = attributeSection.Trim();
			if (!attributeSection.StartsWith("href=".AsSpan(), StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}
			ReadOnlySpan<char> span = attributeSection.Slice("href=".Length);
			char c = ((span.Length > 0) ? span[0] : '\0');
			if (c == '"' || c == '\'')
			{
				ReadOnlySpan<char> span2 = span.Slice(1);
				int num = span2.IndexOf(c);
				if (num == -1)
				{
					return false;
				}
				if (span2.Slice(num + 1).Trim().Length > 0)
				{
					return false;
				}
				hrefValue = span2.Slice(0, num).ToString();
			}
			else
			{
				if (span.Contains(new ReadOnlySpan<char>(new char[1] { ' ' }), StringComparison.OrdinalIgnoreCase))
				{
					return false;
				}
				hrefValue = span.ToString();
			}
			return true;
		}

		private static bool ParseSpriteAttributes(ReadOnlySpan<char> attributeSection, TextSettings textSettings, out char unicode, out TagValue? spriteAssetValue, out TagValue? glyphMetricsValue, out TagValue? tintValue, out TagValue? scaleValue, out TagValue? colorValue, out string? spriteAssetNameOut)
		{
			int num = -1;
			unicode = '\0';
			spriteAssetValue = null;
			glyphMetricsValue = null;
			tintValue = null;
			scaleValue = null;
			colorValue = null;
			spriteAssetNameOut = null;
			ReadOnlySpan<char> readOnlySpan = ReadOnlySpan<char>.Empty;
			ReadOnlySpan<char> readOnlySpan2 = ReadOnlySpan<char>.Empty;
			SpriteAsset target = null;
			while (!attributeSection.IsEmpty)
			{
				attributeSection = attributeSection.TrimStart();
				if (attributeSection.IsEmpty)
				{
					break;
				}
				int num2 = attributeSection.IndexOf('=');
				if (num2 == -1)
				{
					break;
				}
				ReadOnlySpan<char> span = attributeSection.Slice(0, num2).Trim();
				ReadOnlySpan<char> readOnlySpan3 = attributeSection.Slice(num2 + 1).TrimStart();
				char c = ((readOnlySpan3.Length > 0) ? readOnlySpan3[0] : '\0');
				ReadOnlySpan<char> readOnlySpan4;
				if (c == '"' || c == '\'')
				{
					ReadOnlySpan<char> span2 = readOnlySpan3.Slice(1);
					int num3 = span2.IndexOf(c);
					if (num3 == -1)
					{
						break;
					}
					readOnlySpan4 = span2.Slice(0, num3);
					attributeSection = span2.Slice(num3 + 1);
				}
				else
				{
					int num4 = readOnlySpan3.IndexOf(' ');
					if (num4 == -1)
					{
						readOnlySpan4 = readOnlySpan3;
						attributeSection = ReadOnlySpan<char>.Empty;
					}
					else
					{
						readOnlySpan4 = readOnlySpan3.Slice(0, num4);
						attributeSection = readOnlySpan3.Slice(num4);
					}
				}
				if (span.IsEmpty)
				{
					if (int.TryParse(readOnlySpan4, out var result))
					{
						num = result;
					}
					else
					{
						readOnlySpan = readOnlySpan4;
					}
				}
				else if (span.SequenceEqual("name"))
				{
					readOnlySpan2 = readOnlySpan4;
				}
				else if (span.SequenceEqual("index"))
				{
					if (int.TryParse(readOnlySpan4, out var result2))
					{
						num = result2;
					}
				}
				else if (span.SequenceEqual("tint"))
				{
					if (int.TryParse(readOnlySpan4, out var result3) && result3 == 1)
					{
						tintValue = new TagValue(value: true, ValueID.Tint);
					}
				}
				else if (span.SequenceEqual("color"))
				{
					readOnlySpan4 = GetAttributeSpan(readOnlySpan4);
					if (ColorUtility.TryParseHtmlString(readOnlySpan4, out var color))
					{
						colorValue = new TagValue(color, ValueID.SpriteColor);
					}
				}
			}
			if (!readOnlySpan.IsEmpty)
			{
				spriteAssetNameOut = readOnlySpan.ToString();
				if (!s_SpriteAssetCache.TryGetValue(spriteAssetNameOut, out WeakReference<SpriteAsset> value) || !value.TryGetTarget(out target))
				{
					return false;
				}
			}
			else
			{
				if (textSettings.defaultSpriteAsset != null)
				{
					target = textSettings.defaultSpriteAsset;
				}
				else if (TextSettings.s_GlobalSpriteAsset != null)
				{
					target = TextSettings.s_GlobalSpriteAsset;
				}
				if (target == null)
				{
					return false;
				}
			}
			if (!readOnlySpan2.IsEmpty)
			{
				num = target.GetSpriteIndexFromName(readOnlySpan2.ToString());
			}
			if (num == -1)
			{
				return false;
			}
			if (target.spriteCharacterTable.Count <= num)
			{
				return false;
			}
			SpriteCharacter spriteCharacter = target.spriteCharacterTable[num];
			spriteAssetValue = new TagValue(target.instanceID, TagUnitType.Unknown, ValueID.AssetID);
			glyphMetricsValue = new TagValue(spriteCharacter.glyph.metrics, ValueID.GlyphMetrics);
			scaleValue = new TagValue(spriteCharacter.scale, TagUnitType.Unknown, ValueID.Scale);
			unicode = (char)(k_PrivateArea + num);
			return true;
		}

		public static int GetHashCode(ReadOnlySpan<char> span)
		{
			HashCode hashCode = default(HashCode);
			ReadOnlySpan<char> readOnlySpan = span;
			for (int i = 0; i < readOnlySpan.Length; i++)
			{
				char value = readOnlySpan[i];
				hashCode.Add(value);
			}
			return hashCode.ToHashCode();
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
		internal static void PreloadFontAssetsFromTags(string text, TextSettings textSettings)
		{
			if (!HasFontTags(text, textSettings, out List<string> fontAssetNames))
			{
				return;
			}
			foreach (string item in fontAssetNames)
			{
				if (!s_FontAssetCache.ContainsKey(item))
				{
					FontAsset fontAsset = Resources.Load<FontAsset>(textSettings.defaultFontAssetPath + item);
					if (!(fontAsset == null))
					{
						fontAsset.EnsureNativeFontAssetIsCreated();
						s_FontAssetCache[item] = fontAsset.nativeFontAsset;
					}
				}
			}
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
		internal static void PreloadSpriteAssetsFromTags(string text, TextSettings textSettings)
		{
			if (!HasSpriteTags(text, textSettings, out List<string> spriteAssetNames))
			{
				return;
			}
			foreach (string item in spriteAssetNames)
			{
				if (!s_SpriteAssetCache.ContainsKey(item))
				{
					SpriteAsset spriteAsset = Resources.Load<SpriteAsset>(textSettings.defaultSpriteAssetPath + item);
					if (!(spriteAsset == null))
					{
						spriteAsset.UpdateLookupTables();
						s_SpriteAssetCache[item] = new WeakReference<SpriteAsset>(spriteAsset);
					}
				}
			}
		}

		internal static List<Tag> FindTags(ref string inputStr, TextSettings textSettings, bool preprocessingOnly = false, List<ParseError>? errors = null)
		{
			char[] array = inputStr.ToCharArray();
			List<Tag> list = new List<Tag>();
			int num = 0;
			while (true)
			{
				int num2 = Array.IndexOf(array, '<', num);
				if (num2 == -1)
				{
					break;
				}
				int num3 = Array.IndexOf(array, '>', num2);
				if (num3 == -1)
				{
					break;
				}
				bool flag = array.Length > num2 + 1 && array[num2 + 1] == '/';
				if (num3 == num2 + 1)
				{
					errors?.Add(new ParseError("Empty tag", num2));
					num = num3 + 1;
					continue;
				}
				num = num3 + 1;
				TagType tagType2;
				string error2;
				ReadOnlySpan<char> attribute2;
				if (!flag)
				{
					Span<char> span = array.AsSpan(num2 + 1, num3 - num2 - 1);
					if (SpanToEnum(span, out TagType tagType, out string error, out ReadOnlySpan<char> attribute))
					{
						TagValue spriteAssetValue = null;
						TagValue glyphMetricsValue = null;
						if (tagType == TagType.Color)
						{
							spriteAssetValue = ParseColorAttribute(attribute);
							if ((object)spriteAssetValue == null)
							{
								errors?.Add(new ParseError("Invalid color value", num2));
								num = num2 + 1;
								continue;
							}
						}
						if (tagType == TagType.Mark)
						{
							spriteAssetValue = ParseColorAttribute(attribute);
							if (spriteAssetValue == null)
							{
								while (!attribute.IsEmpty)
								{
									int num4 = attribute.IndexOf(' ');
									ReadOnlySpan<char> span2;
									if (num4 >= 0)
									{
										span2 = attribute.Slice(0, num4);
										attribute = ((num4 + 1 >= attribute.Length) ? ReadOnlySpan<char>.Empty : attribute.Slice(num4 + 1));
									}
									else
									{
										span2 = attribute;
										attribute = ReadOnlySpan<char>.Empty;
									}
									int num5 = span2.IndexOf('=');
									if (num5 > 0 && num5 < span2.Length - 1)
									{
										ReadOnlySpan<char> span3 = span2.Slice(0, num5);
										ReadOnlySpan<char> readOnlySpan = span2.Slice(num5 + 1);
										if (span3.SequenceEqual("color"))
										{
											spriteAssetValue = ParseColorAttribute(readOnlySpan);
										}
										else if (span3.SequenceEqual("padding"))
										{
											glyphMetricsValue = ParsePaddingAttribute(readOnlySpan);
										}
									}
								}
							}
						}
						if (tagType == TagType.Hyperlink)
						{
							spriteAssetValue = ParseHref(attribute);
						}
						if (tagType == TagType.Link)
						{
							attribute = GetAttributeSpan(attribute);
							string value = attribute.ToString();
							spriteAssetValue = new TagValue(value);
						}
						switch (tagType)
						{
						case TagType.Sprite:
						{
							if (!ParseSpriteAttributes(attribute, textSettings, out char unicode, out spriteAssetValue, out glyphMetricsValue, out TagValue tintValue, out TagValue scaleValue, out TagValue colorValue, out string spriteAssetNameOut))
							{
								if (preprocessingOnly && spriteAssetNameOut != null)
								{
									list.Add(new Tag
									{
										tagType = tagType,
										start = num2,
										end = num3,
										isClosing = false,
										value = new TagValue(spriteAssetNameOut)
									});
								}
								continue;
							}
							list.Add(new Tag
							{
								tagType = tagType,
								start = num2,
								end = num3,
								isClosing = false,
								value = spriteAssetValue,
								value2 = glyphMetricsValue,
								value3 = tintValue,
								value4 = scaleValue,
								value5 = colorValue
							});
							inputStr = inputStr.Insert(num3 + 1, unicode + "/");
							array = inputStr.ToCharArray();
							list.Add(new Tag
							{
								tagType = tagType,
								start = num3 + 2,
								end = num3 + 2,
								isClosing = true,
								value = spriteAssetValue,
								value2 = glyphMetricsValue,
								value3 = tintValue,
								value4 = scaleValue,
								value5 = colorValue
							});
							num = num3 + 2;
							continue;
						}
						case TagType.Br:
							if (attribute.IsEmpty)
							{
								list.Add(new Tag
								{
									tagType = tagType,
									start = num2,
									end = num3,
									isClosing = false,
									value = null
								});
								inputStr = inputStr.Insert(num3 + 1, "\n/");
								array = inputStr.ToCharArray();
								list.Add(new Tag
								{
									tagType = tagType,
									start = num3 + 2,
									end = num3 + 2,
									isClosing = true,
									value = null
								});
								num = num3 + 2;
							}
							continue;
						case TagType.Align:
						{
							attribute = GetAttributeSpan(attribute);
							string value2 = attribute.ToString();
							if (Enum.TryParse<HorizontalAlignment>(value2, ignoreCase: true, out var _))
							{
								spriteAssetValue = new TagValue(value2);
							}
							if ((object)spriteAssetValue == null)
							{
								errors?.Add(new ParseError($"Invalid {tagType} value", num2));
								num = num2 + 1;
								continue;
							}
							break;
						}
						}
						if (tagType == TagType.Mspace || tagType == TagType.CSpace)
						{
							TagUnitType tagUnitType = ParseTagUnitType(ref attribute);
							switch (tagUnitType)
							{
							case TagUnitType.Percentage:
								errors?.Add(new ParseError($"Invalid {tagUnitType} value", num2));
								num = num2 + 1;
								continue;
							case TagUnitType.Unknown:
								tagUnitType = TagUnitType.Pixels;
								break;
							}
							attribute = GetAttributeSpan(attribute);
							if (!float.TryParse(attribute, NumberStyles.Float, CultureInfo.InvariantCulture, out var result2))
							{
								errors?.Add(new ParseError("Invalid numerical value", num2));
								num = num2 + 1;
								continue;
							}
							spriteAssetValue = new TagValue(result2, tagUnitType);
						}
						if (tagType == TagType.Margin || tagType == TagType.MarginLeft || tagType == TagType.MarginRight)
						{
							TagUnitType tagUnitType2 = ParseTagUnitType(ref attribute);
							if (tagUnitType2 == TagUnitType.Unknown)
							{
								tagUnitType2 = TagUnitType.Pixels;
							}
							attribute = GetAttributeSpan(attribute);
							if (!float.TryParse(attribute, NumberStyles.Float, CultureInfo.InvariantCulture, out var result3))
							{
								errors?.Add(new ParseError("Invalid numerical value", num2));
								num = num2 + 1;
								continue;
							}
							spriteAssetValue = new TagValue(result3, tagUnitType2);
						}
						if (tagType == TagType.Font)
						{
							attribute = GetAttributeSpan(attribute);
							string text = attribute.ToString();
							if (string.IsNullOrEmpty(text))
							{
								errors?.Add(new ParseError("Font name cannot be empty", num2));
								num = num2 + 1;
								continue;
							}
							if (!s_FontAssetCache.ContainsKey(text))
							{
								if (preprocessingOnly)
								{
									list.Add(new Tag
									{
										tagType = tagType,
										start = num2,
										end = num3,
										isClosing = false,
										value = new TagValue(text)
									});
								}
								num = num2 + 1;
								continue;
							}
							spriteAssetValue = new TagValue(text);
						}
						if (tagType == TagType.Size)
						{
							TagUnitType tagUnitType3 = ParseTagUnitType(ref attribute);
							if (tagUnitType3 == TagUnitType.Unknown)
							{
								tagUnitType3 = TagUnitType.Pixels;
							}
							attribute = GetAttributeSpan(attribute);
							bool value3 = false;
							if (attribute.Length > 0 && (attribute[0] == '+' || attribute[0] == '-'))
							{
								value3 = true;
							}
							if (!float.TryParse(attribute, NumberStyles.Float, CultureInfo.InvariantCulture, out var result4))
							{
								errors?.Add(new ParseError("Invalid size value", num2));
								num = num2 + 1;
								continue;
							}
							spriteAssetValue = new TagValue(result4, tagUnitType3);
							glyphMetricsValue = new TagValue(value3);
						}
						if (tagType == TagType.FontWeight)
						{
							attribute = GetAttributeSpan(attribute);
							if (!int.TryParse(attribute, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result5))
							{
								errors?.Add(new ParseError("Invalid font-weight value", num2));
								num = num2 + 1;
								continue;
							}
							if (!Enum.IsDefined(typeof(TextFontWeight), result5))
							{
								errors?.Add(new ParseError($"Invalid font-weight value: {result5}", num2));
								num = num2 + 1;
								continue;
							}
							spriteAssetValue = new TagValue(result5);
						}
						list.Add(new Tag
						{
							tagType = tagType,
							start = num2,
							end = num3,
							isClosing = flag,
							value = spriteAssetValue,
							value2 = glyphMetricsValue
						});
						if (tagType == TagType.NoParse)
						{
							if ((num2 = array.AsSpan(num).IndexOf("</noparse>")) == -1)
							{
								break;
							}
							num2 += num;
							num3 = num2 + "</noparse>".Length - 1;
							list.Add(new Tag
							{
								tagType = TagType.NoParse,
								start = num2,
								end = num3,
								isClosing = true
							});
							num = num3 + 1;
						}
					}
					else
					{
						if (error != null)
						{
							errors?.Add(new ParseError(error, num2));
						}
						num = num2 + 1;
					}
				}
				else if (SpanToEnum(array.AsSpan(num2 + 2, num3 - num2 - 2), out tagType2, out error2, out attribute2))
				{
					list.Add(new Tag
					{
						tagType = tagType2,
						start = num2,
						end = num3,
						isClosing = flag
					});
				}
				else
				{
					if (error2 != null)
					{
						errors?.Add(new ParseError(error2, num2));
					}
					num = num2 + 1;
				}
			}
			return list;
		}

		private static ReadOnlySpan<char> GetAttributeSpan(ReadOnlySpan<char> attributeSection)
		{
			if (attributeSection.Length >= 1 && attributeSection[0] == '=')
			{
				attributeSection = attributeSection.Slice(1);
			}
			if (attributeSection.Length >= 2)
			{
				if (attributeSection[0] == '"')
				{
					if (attributeSection[attributeSection.Length - 1] == '"')
					{
						goto IL_0082;
					}
				}
				if (attributeSection[0] == '\'')
				{
					if (attributeSection[attributeSection.Length - 1] == '\'')
					{
						goto IL_0082;
					}
				}
			}
			return attributeSection;
			IL_0082:
			return attributeSection.Slice(1, attributeSection.Length - 2);
		}

		private static TagUnitType ParseTagUnitType(ref ReadOnlySpan<char> attributeSection)
		{
			if (attributeSection.EndsWith("em".AsSpan(), StringComparison.OrdinalIgnoreCase))
			{
				attributeSection = attributeSection.Slice(0, attributeSection.Length - 2);
				return TagUnitType.FontUnits;
			}
			if (attributeSection.EndsWith("px".AsSpan(), StringComparison.OrdinalIgnoreCase))
			{
				attributeSection = attributeSection.Slice(0, attributeSection.Length - 2);
				return TagUnitType.Pixels;
			}
			if (attributeSection.EndsWith("%".AsSpan(), StringComparison.OrdinalIgnoreCase))
			{
				attributeSection = attributeSection.Slice(0, attributeSection.Length - 1);
				return TagUnitType.Percentage;
			}
			return TagUnitType.Unknown;
		}

		internal static List<Tag> PickResultingTags(List<Tag> allTags, string input, int atPosition, List<Tag>? applicableTags = null)
		{
			if (applicableTags == null)
			{
				applicableTags = new List<Tag>();
			}
			else
			{
				applicableTags.Clear();
			}
			int num = 0;
			Debug.Assert(string.IsNullOrEmpty(input) || (atPosition < input.Length && atPosition >= 0), "Invalid position");
			Debug.Assert(num <= atPosition && num >= 0, "Invalid starting position");
			int num2 = 0;
			foreach (Tag allTag in allTags)
			{
				Debug.Assert(allTag.start >= num2, "Tags are not sorted");
				num2 = allTag.end + 1;
			}
			foreach (Tag applicableTag in applicableTags)
			{
				Debug.Assert(applicableTag.end <= num, "Tag end pass the point where we should start parsing");
				Debug.Assert(allTags.Contains(applicableTag));
			}
			Span<int?> span = stackalloc int?[allTags.Count];
			Span<int?> span2 = stackalloc int?[TagsInfo.Length];
			int num3 = -1;
			foreach (Tag allTag2 in allTags)
			{
				num3++;
				if (allTag2.end < num || allTag2.tagType == TagType.NoParse)
				{
					continue;
				}
				if (allTag2.start > atPosition)
				{
					break;
				}
				if (allTag2.isClosing)
				{
					if (span2[(int)allTag2.tagType].HasValue)
					{
						if (span[num3].HasValue)
						{
							span2[(int)allTag2.tagType] = span[num3];
						}
						else
						{
							span2[(int)allTag2.tagType] = null;
						}
					}
				}
				else
				{
					int? num4 = span2[(int)allTag2.tagType];
					if (num4.HasValue)
					{
						span[num3] = num4;
					}
					span2[(int)allTag2.tagType] = num3;
				}
			}
			int num5 = 0;
			foreach (Tag allTag3 in allTags)
			{
				int? num6 = span2[(int)allTag3.tagType];
				if (num6.HasValue && num5 == num6.Value)
				{
					applicableTags.Add(allTag3);
				}
				num5++;
			}
			return applicableTags;
		}

		internal static Segment[] GenerateSegments(string input, List<Tag> tags)
		{
			List<Segment> list = new List<Segment>();
			int num = 0;
			for (int i = 0; i < tags.Count; i++)
			{
				Debug.Assert(tags[i].start >= num);
				if (tags[i].start > num)
				{
					list.Add(new Segment
					{
						start = num,
						end = tags[i].start - 1
					});
				}
				num = tags[i].end + 1;
			}
			if (num < input.Length)
			{
				list.Add(new Segment
				{
					start = num,
					end = input.Length - 1
				});
			}
			return list.ToArray();
		}

		internal static void ApplyStateToSegment(string input, List<Tag> tags, Segment[] segments)
		{
			for (int i = 0; i < segments.Length; i++)
			{
				segments[i].tags = PickResultingTags(tags, input, segments[i].start);
			}
		}

		private static int AddLink(TagType type, string value, List<(int, TagType, string)> links)
		{
			foreach (var (result, tagType, text) in links)
			{
				if (type == tagType && value == text)
				{
					return result;
				}
			}
			int count = links.Count;
			links.Add((count, type, value));
			return count;
		}

		private static TextSpan CreateTextSpan(Segment segment, ref NativeTextGenerationSettings tgs, List<(int, TagType, string)> links, Color hyperlinkColor, float pixelsPerPoint)
		{
			TextSpan result = tgs.CreateTextSpan();
			if (segment.tags == null)
			{
				return result;
			}
			for (int i = 0; i < segment.tags.Count; i++)
			{
				switch (segment.tags[i].tagType)
				{
				case TagType.Bold:
					result.fontWeight = TextFontWeight.Bold;
					break;
				case TagType.Italic:
					result.fontStyle |= FontStyles.Italic;
					break;
				case TagType.Underline:
					result.fontStyle |= FontStyles.Underline;
					break;
				case TagType.Strikethrough:
					result.fontStyle |= FontStyles.Strikethrough;
					break;
				case TagType.Subscript:
					result.fontStyle |= FontStyles.Subscript;
					break;
				case TagType.Superscript:
					result.fontStyle |= FontStyles.Superscript;
					break;
				case TagType.AllCaps:
				case TagType.Uppercase:
					result.fontStyle |= FontStyles.UpperCase;
					break;
				case TagType.Lowercase:
				case TagType.SmallCaps:
					result.fontStyle |= FontStyles.LowerCase;
					break;
				case TagType.Color:
					result.color = segment.tags[i].value.ColorValue;
					break;
				case TagType.Mark:
				{
					result.fontStyle |= FontStyles.Highlight;
					TagValue? value9 = segment.tags[i].value;
					if ((object)value9 != null && value9.ID == ValueID.Color)
					{
						result.highlightColor = segment.tags[i].value.ColorValue;
					}
					else
					{
						result.highlightColor = k_HighlightColor;
					}
					TagValue? value10 = segment.tags[i].value2;
					if ((object)value10 != null && value10.ID == ValueID.Padding)
					{
						result.highlightPadding = segment.tags[i].value2.Vector4Value;
					}
					break;
				}
				case TagType.Font:
				{
					string text = segment.tags[i].value?.StringValue ?? "";
					if (!string.IsNullOrEmpty(text) && s_FontAssetCache.TryGetValue(text, out var value7))
					{
						result.fontAsset = value7;
					}
					break;
				}
				case TagType.FontWeight:
				{
					TagValue? value6 = segment.tags[i].value;
					if ((object)value6 != null && value6.type == TagValueType.NumericalValue)
					{
						result.fontWeight = (TextFontWeight)segment.tags[i].value.NumericalValue;
					}
					break;
				}
				case TagType.Hyperlink:
					result.linkID = AddLink(TagType.Hyperlink, segment.tags[i].value?.StringValue ?? "", links);
					result.color = hyperlinkColor;
					result.fontStyle |= FontStyles.Underline;
					break;
				case TagType.Link:
					result.linkID = AddLink(TagType.Link, segment.tags[i].value?.StringValue ?? "", links);
					break;
				case TagType.Sprite:
				{
					TagValue? value = segment.tags[i].value;
					if ((object)value != null && value.ID == ValueID.AssetID)
					{
						result.spriteID = (int)segment.tags[i].value.NumericalValue;
					}
					TagValue? value2 = segment.tags[i].value2;
					if ((object)value2 != null && value2.ID == ValueID.GlyphMetrics)
					{
						result.spriteMetrics = segment.tags[i].value2.GlyphMetricsValue;
					}
					TagValue? value3 = segment.tags[i].value3;
					if ((object)value3 != null && value3.ID == ValueID.Tint)
					{
						result.spriteTint = segment.tags[i].value3.BoolValue;
					}
					TagValue? value4 = segment.tags[i].value4;
					if ((object)value4 != null && value4.ID == ValueID.Scale)
					{
						result.spriteScale = (int)segment.tags[i].value4.NumericalValue;
					}
					TagValue? value5 = segment.tags[i].value5;
					if ((object)value5 != null && value5.ID == ValueID.SpriteColor)
					{
						result.spriteColor = segment.tags[i].value5.ColorValue;
					}
					else
					{
						result.spriteColor = Color.white;
					}
					break;
				}
				case TagType.Size:
				{
					float numericalValue = segment.tags[i].value.NumericalValue;
					TagUnitType unit = segment.tags[i].value.unit;
					TagValue? value8 = segment.tags[i].value2;
					if ((object)value8 != null && value8.BoolValue)
					{
						float num4 = (float)tgs.fontSize / 64f;
						float num5 = numericalValue * pixelsPerPoint;
						float num6 = num4 + num5;
						result.fontSize = (int)Math.Round(num6 * 64f, MidpointRounding.AwayFromZero);
						break;
					}
					if (numericalValue <= 0f)
					{
						result.fontSize = 0;
						break;
					}
					switch (unit)
					{
					case TagUnitType.FontUnits:
					{
						float num9 = (float)tgs.fontSize / 64f;
						float num10 = numericalValue * num9;
						result.fontSize = (int)Math.Round(num10 * 64f, MidpointRounding.AwayFromZero);
						break;
					}
					case TagUnitType.Percentage:
					{
						float num7 = (float)tgs.fontSize / 64f;
						float num8 = numericalValue / 100f * num7;
						result.fontSize = (int)Math.Round(num8 * 64f, MidpointRounding.AwayFromZero);
						break;
					}
					default:
						result.fontSize = (int)Math.Round(numericalValue * pixelsPerPoint * 64f, MidpointRounding.AwayFromZero);
						break;
					}
					break;
				}
				case TagType.CSpace:
				{
					float num3 = ((segment.tags[i].value.unit == TagUnitType.Pixels) ? (pixelsPerPoint * 64f) : 64f);
					result.cspace = (int)(segment.tags[i].value.NumericalValue * num3);
					result.cspaceUnitType = segment.tags[i].value.unit;
					break;
				}
				case TagType.Mspace:
				{
					float num2 = ((segment.tags[i].value.unit == TagUnitType.Pixels) ? (pixelsPerPoint * 64f) : 64f);
					result.mspace = (int)(segment.tags[i].value.NumericalValue * num2);
					result.mspaceUnitType = segment.tags[i].value.unit;
					break;
				}
				case TagType.Align:
					Enum.TryParse<HorizontalAlignment>(segment.tags[i].value.StringValue, ignoreCase: true, out result.alignment);
					break;
				case TagType.Margin:
				case TagType.MarginLeft:
				case TagType.MarginRight:
				{
					float num = ((segment.tags[i].value.unit == TagUnitType.Pixels) ? (pixelsPerPoint * 64f) : 64f);
					result.margin = (int)(segment.tags[i].value.NumericalValue * num);
					result.marginUnitType = segment.tags[i].value.unit;
					TagType tagType = segment.tags[i].tagType;
					if (1 == 0)
					{
					}
					MarginDirection marginDirection = tagType switch
					{
						TagType.Margin => MarginDirection.Both, 
						TagType.MarginLeft => MarginDirection.Left, 
						TagType.MarginRight => MarginDirection.Right, 
						_ => MarginDirection.Both, 
					};
					if (1 == 0)
					{
					}
					result.marginDirection = marginDirection;
					break;
				}
				case TagType.NoParse:
				case TagType.Unknown:
					throw new InvalidOperationException("Invalid tag type" + segment.tags[i].tagType);
				}
			}
			return result;
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
		internal static void CreateTextGenerationSettingsArray(ref NativeTextGenerationSettings tgs, List<(int, TagType, string)> links, Color hyperlinkColor, float pixelsPerPoint, TextSettings textSettings)
		{
			links.Clear();
			List<Tag> tags = FindTags(ref tgs.text, textSettings);
			Segment[] array = GenerateSegments(tgs.text, tags);
			ApplyStateToSegment(tgs.text, tags, array);
			StringBuilder stringBuilder = new StringBuilder(tgs.text.Length);
			tgs.textSpans = new TextSpan[array.Length];
			int num = 0;
			for (int i = 0; i < array.Length; i++)
			{
				Segment segment = array[i];
				string text = tgs.text.Substring(segment.start, segment.end + 1 - segment.start);
				TextSpan textSpan = CreateTextSpan(segment, ref tgs, links, hyperlinkColor, pixelsPerPoint);
				textSpan.startIndex = num;
				textSpan.length = text.Length;
				tgs.textSpans[i] = textSpan;
				stringBuilder.Append(text);
				num += text.Length;
			}
			tgs.text = stringBuilder.ToString();
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
		internal static bool MayNeedParsing(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return false;
			}
			ReadOnlySpan<char> span = text.AsSpan();
			int num = span.IndexOf('<');
			if (num < 0 || num >= span.Length - 1)
			{
				return false;
			}
			return span.Slice(num + 1).IndexOf('>') >= 0;
		}

		private static bool ContainsFontTag(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return false;
			}
			ReadOnlySpan<char> span = text.AsSpan();
			ReadOnlySpan<char> value = "<font=".AsSpan();
			int num = span.IndexOf(value, StringComparison.Ordinal);
			if (num < 0)
			{
				return false;
			}
			int num2 = num + value.Length;
			for (int i = num2; i < span.Length; i++)
			{
				if (span[i] == '>')
				{
					return true;
				}
			}
			return false;
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
		internal static bool ContainsSpriteTag(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return false;
			}
			ReadOnlySpan<char> span = text.AsSpan();
			ReadOnlySpan<char> value = "<sprite".AsSpan();
			int num = span.IndexOf(value, StringComparison.Ordinal);
			if (num < 0)
			{
				return false;
			}
			int num2 = num + value.Length;
			for (int i = num2; i < span.Length; i++)
			{
				if (span[i] == '>')
				{
					return true;
				}
			}
			return false;
		}

		internal static bool ContainsStyleTags(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return false;
			}
			ReadOnlySpan<char> span = text.AsSpan();
			ReadOnlySpan<char> value = "<style=\"".AsSpan();
			int num = span.IndexOf(value, StringComparison.Ordinal);
			if (num < 0)
			{
				return false;
			}
			int num2 = num + value.Length;
			for (int i = num2; i < span.Length; i++)
			{
				if (span[i] == '>')
				{
					return true;
				}
			}
			return false;
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule", "UnityEngine.IMGUIModule" })]
		internal static bool HasFontTags(string text, TextSettings textSettings, out List<string> fontAssetNames)
		{
			fontAssetNames = new List<string>();
			if (!ContainsFontTag(text))
			{
				return false;
			}
			List<Tag> list = FindTags(ref text, textSettings, preprocessingOnly: true);
			foreach (Tag item in list)
			{
				if (item.tagType == TagType.Font && !item.isClosing && item.value?.StringValue != null)
				{
					string stringValue = item.value.StringValue;
					if (!fontAssetNames.Contains(stringValue))
					{
						fontAssetNames.Add(stringValue);
					}
				}
			}
			return fontAssetNames.Count > 0;
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule", "UnityEngine.IMGUIModule" })]
		internal static bool HasSpriteTags(string text, TextSettings textSettings, out List<string> spriteAssetNames)
		{
			spriteAssetNames = new List<string>();
			if (!ContainsSpriteTag(text))
			{
				return false;
			}
			List<Tag> list = FindTags(ref text, textSettings, preprocessingOnly: true);
			foreach (Tag item in list)
			{
				if (item.tagType != TagType.Sprite || item.isClosing)
				{
					continue;
				}
				TagValue? value = item.value;
				if ((object)value != null && value.type == TagValueType.StringValue)
				{
					string stringValue = item.value.StringValue;
					if (!string.IsNullOrEmpty(stringValue) && !spriteAssetNames.Contains(stringValue))
					{
						spriteAssetNames.Add(stringValue);
					}
				}
			}
			return spriteAssetNames.Count > 0;
		}
	}
}
