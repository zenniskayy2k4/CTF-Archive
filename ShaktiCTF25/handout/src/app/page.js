import Image from "next/image";
import styles from "./page.module.css";

export default function Home() {
  return (
    <div className={styles.page}>
      <main className={styles.main}>
          <li>
            Challenge is to access admin page:<a href="/admin">/admin</a>
          </li>
        
        </ul>
        <div className={styles.ctas}>
        </div>
      </main>
   
    </div>
  );
}
