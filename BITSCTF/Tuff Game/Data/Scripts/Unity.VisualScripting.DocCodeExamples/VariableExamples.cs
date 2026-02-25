using Unity.VisualScripting;
using UnityEngine;

internal class VariableExamples
{
	public class PlayerController : MonoBehaviour
	{
		private VariableDeclaration m_Velocity;

		private void Start()
		{
			Variables component = GetComponent<Variables>();
			m_Velocity = component.declarations.GetDeclaration("velocity");
		}

		private void Update()
		{
			if (Input.GetKeyDown("space"))
			{
				float num = (float)m_Velocity.value;
				m_Velocity.value = num * 2f;
			}
		}
	}
}
