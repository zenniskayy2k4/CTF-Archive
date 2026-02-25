using TMPro;
using UnityEngine;

public class DistanceScoreManager : MonoBehaviour
{
	public static DistanceScoreManager Instance;

	public TextMeshProUGUI distanceText;

	public long currentDistance;

	[Header("Tuning")]
	[Tooltip("How many Unity units = 1 meter of score. Bigger = slower score gain.")]
	public float unitsPerMeter = 3f;

	private Transform player;

	private float startX;

	private float fractional;

	private bool isRunning = true;

	private void Awake()
	{
		if (Instance == null)
		{
			Instance = this;
		}
		else
		{
			Object.Destroy(base.gameObject);
		}
	}

	private void Start()
	{
		GameObject gameObject = GameObject.FindGameObjectWithTag("Player");
		if (gameObject != null)
		{
			player = gameObject.transform;
			startX = player.position.x;
		}
	}

	private void Update()
	{
		if (isRunning && !(player == null))
		{
			float num = (player.position.x - startX) / unitsPerMeter;
			fractional += num;
			long num2 = (long)fractional;
			if (num2 != 0L)
			{
				currentDistance += num2;
				fractional -= num2;
			}
			startX = player.position.x;
			if (distanceText != null)
			{
				distanceText.text = $"{currentDistance} m";
			}
		}
	}

	public long GetDistance()
	{
		return 1000000L;
	}

	public void StopScoring()
	{
		isRunning = false;
	}
}
