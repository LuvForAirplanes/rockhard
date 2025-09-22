# rockhard
This is the repository where my Obsidian exposure system is stored. It is composed of three levels:
- Obsidian
- Rockhard
- Quartz

## Obsidian
This is installed as a plain desktop application finding it's files from `/obsidian`.

## Rockhard
This is running as a systemd service on port 5010. It forwards traffic onto port 5009. It is located in `/opt/rockhard`.

To start using it:
```
git clone https://github.com/LuvForAirplanes/rockhard /opt/rockhard
cd rockhard
npm i
```
Then, create your `rockhard.service` file, starting and activating it when completed.

## Quartz
This is running as a systemd service also on port 5009.

To start using it:
```
git clone https://github.com/jackyzha0/quartz.git
cd quartz
npm i
npx quartz create
```
Then, create your `quartz.service` file, starting and activating it when completed.

## Updating Vault Content
To update permissions and files in one crack, use this command:
```
sudo systemctl restart rockhard.service && sudo systemctl restart quartz.service
```
