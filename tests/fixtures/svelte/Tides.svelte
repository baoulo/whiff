<script>
  import { onMount } from 'svelte';
  import Chart from './Chart.svelte';
  let tides = [];
  onMount(async () => { tides = await (await fetch('/tides')).json(); });
</script>

<!-- tide chart -->
<Chart data={tides} />

<style>
  :global(body) { margin: 0; }
</style>
