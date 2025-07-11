# Standard-Library Functions

These functions serve as lightweight commands without crowding the `/<command>`
namespace.


| Function                 | Description                                                     |
|--------------------------|-----------------------------------------------------------------|
| `/std now`               | Displays the current date and time.                             |
| `/std new-day-alert`     | Makes AI aware when a new day begins since the last interaction.|
| `/std which <prog>`      | Checks if a specific program is available.                      |

Using `/std now` is preferable to `/exec date`, as the latter requires user
confirmation to execute in untrusted tasks. The same reasoning applies to
`/std which` instead of `/exec which`.

The `/std new-day-alert` function is essential for ongoing, multi-day
conversations (e.g., calendar tasks). It ensures the AI is aware of a day
change so it can handle relative dates accurately.
