using UnityEngine;

public class EnemySpawner : MonoBehaviour
{
	public GameObject[] enemyPrefabs;

	public float spawnRate = 1.5f;

	public float spawnAheadDistance = 12f;

	public float minY = -4f;

	public float maxY = 4f;

	private Transform player;

	private void Start()
	{
		player = GameObject.FindGameObjectWithTag("Player").transform;
		InvokeRepeating("SpawnEnemy", 1f, spawnRate);
	}

	private void SpawnEnemy()
	{
		Vector3 position = new Vector3(player.position.x + spawnAheadDistance, Random.Range(minY, maxY), 0f);
		int num = Random.Range(0, enemyPrefabs.Length);
		Object.Instantiate(enemyPrefabs[num], position, Quaternion.identity);
	}
}
