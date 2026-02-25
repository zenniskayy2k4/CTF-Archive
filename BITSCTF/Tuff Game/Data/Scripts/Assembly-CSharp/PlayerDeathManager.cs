using UnityEngine;

public class PlayerDeathManager : MonoBehaviour
{
	public static PlayerDeathManager Instance;

	[Header("Death Screen")]
	public GameObject deathScreenUI;

	[Header("Enemy Cleanup")]
	public string enemyTag = "Enemy";

	public LayerMask enemyLayer;

	private bool hasDied;

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

	public void HandlePlayerDeath()
	{
		Debug.Log("PLAYER DEATH TRIGGERED");
		if (!hasDied)
		{
			hasDied = true;
			DistanceScoreManager.Instance?.StopScoring();
			DespawnAllEnemies();
			Time.timeScale = 0f;
			if (deathScreenUI != null)
			{
				deathScreenUI.SetActive(value: true);
			}
		}
	}

	private void DespawnAllEnemies()
	{
		GameObject[] array = GameObject.FindGameObjectsWithTag(enemyTag);
		for (int i = 0; i < array.Length; i++)
		{
			Object.Destroy(array[i]);
		}
		array = Object.FindObjectsOfType<GameObject>();
		foreach (GameObject gameObject in array)
		{
			if (((1 << gameObject.layer) & (int)enemyLayer) != 0)
			{
				Object.Destroy(gameObject);
			}
		}
	}
}
