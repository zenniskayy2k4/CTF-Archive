using UnityEngine;

public class EnemyLockOn : EnemyBase
{
	public float diveSpeed = 6f;

	private Vector3 direction;

	private bool locked;

	protected override void Update()
	{
		base.Update();
		if (!locked && player != null)
		{
			direction = (player.position - base.transform.position).normalized;
			locked = true;
		}
		base.transform.position += direction * diveSpeed * Time.deltaTime;
	}
}
