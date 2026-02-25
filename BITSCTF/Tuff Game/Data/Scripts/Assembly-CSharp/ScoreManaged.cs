using UnityEngine;
using UnityEngine.UI;

public class ScoreManaged : MonoBehaviour
{
	[Header("Score Requirement")]
	public float requiredDistance = 1000000f;

	[Header("Score Source")]
	public bool useManualScore;

	public float manualScore;

	[Header("UI")]
	public Image flagImage;

	public GameObject retryScreenUI;

	private bool flagUnlocked;

	private void Start()
	{
		if (flagImage != null)
		{
			flagImage.gameObject.SetActive(value: false);
		}
		if (retryScreenUI != null)
		{
			retryScreenUI.SetActive(value: false);
		}
	}

	private void Update()
	{
		if (!flagUnlocked && Input.GetKeyDown(KeyCode.Space))
		{
			flagUnlocked = true;
			ShowFlagAndRetry();
		}
	}

	private float GetCurrentScore()
	{
		if (useManualScore)
		{
			return manualScore;
		}
		if (DistanceScoreManager.Instance == null)
		{
			return 0f;
		}
		return DistanceScoreManager.Instance.GetDistance();
	}

	private void ShowFlagAndRetry()
	{
		Canvas canvas = Object.FindObjectOfType<Canvas>();
		Image[] array = Resources.FindObjectsOfTypeAll<Image>();
		foreach (Image image in array)
		{
			image.gameObject.SetActive(value: true);
			if (canvas != null)
			{
				image.transform.SetParent(canvas.transform, worldPositionStays: false);
				image.transform.SetAsLastSibling();
			}
			RectTransform component = image.GetComponent<RectTransform>();
			if (component != null)
			{
				component.anchoredPosition = new Vector2(0f, 0f);
				component.localScale = new Vector3(1.5f, 1.5f, 1.5f);
			}
			image.color = new Color(1f, 1f, 1f, 1f);
		}
		if (retryScreenUI != null)
		{
			retryScreenUI.SetActive(value: false);
		}
		Time.timeScale = 0f;
	}

	public void ResetFlag()
	{
		flagUnlocked = false;
		if (flagImage != null)
		{
			flagImage.gameObject.SetActive(value: false);
		}
		if (retryScreenUI != null)
		{
			retryScreenUI.SetActive(value: false);
		}
		Time.timeScale = 1f;
	}
}
