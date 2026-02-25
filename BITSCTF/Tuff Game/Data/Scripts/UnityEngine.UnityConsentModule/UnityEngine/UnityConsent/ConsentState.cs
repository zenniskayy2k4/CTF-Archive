namespace UnityEngine.UnityConsent
{
	public struct ConsentState
	{
		public ConsentStatus AdsIntent;

		public ConsentStatus AnalyticsIntent;

		public ConsentState()
		{
			AdsIntent = ConsentStatus.Unspecified;
			AnalyticsIntent = ConsentStatus.Unspecified;
		}

		public override string ToString()
		{
			return string.Format("{0}: {1}, {2}: {3}", "AdsIntent", AdsIntent, "AnalyticsIntent", AnalyticsIntent);
		}
	}
}
